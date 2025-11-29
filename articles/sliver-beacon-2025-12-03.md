---
title: "リバーシングで読み解くSliver Beaconのシンボル難読化"
emoji: "🥷"
type: "tech" # tech: 技術記事 / idea: アイデア
topics: [Security, reversing, Windows]
published: false
---

# はじめに
:::message
これは [RWPL Advent Calendar 2025](https://adventar.org/calendars/11609) の3日目の記事です。
:::

C2フレームワークとして知られる[Sliver](https://github.com/BishopFox/sliver)のビーコンについて、そのシンボル難読化手法をリバースエンジニアリングから見ていきます。「コード追えばいいじゃん」はドMリバーサールートから外れるのでNGです。

# Sliverとは
SliverはオープンソースのC2フレームワークでペンテストに使われたりしてます。以下の様に実際の攻撃者にも使われてしまってるツールです。

https://thehackernews.com/2025/08/apache-activemq-flaw-exploited-to.html

詳しくは以下のドキュメントを参照してください。

https://sliver.sh/docs

## シンボル難読化

Sliverのビーコンを作成するときのコマンドは以下の様なものです。適当にHTTPのリスナーを指定して実施しました。
```
generate beacon --http IP:Port -N mybeacon
```
この時に生成されるexeファイルがビーコンです。このビーコンはデフォルトでシンボルを難読化する処理が入ります。
このビーコン作成の際に`--skip-symbols`のオプションを指定するとシンボル難読化をスキップできます。

この2つのビーコン作成方法で生成されたexeファイルを比較しながら読み解いていこうと思います。

# リバースエンジニアリング
## ビーコン作成
適当に以下の様にビーコンを作成します。

![1](/images/sliver-beacon/1.png)

`tak.exe`はシンボル難読化がされているビーコン、`tak-skip.exe`はシンボル難読化がスキップされているビーコンです。

![2](/images/sliver-beacon/2.png)

サイズが違いますね。

## エントロピー
適当にエントロピーを見てみます。

+ tak.exe
![3](/images/sliver-beacon/3.png)

+ tak-skip.exe
![4](/images/sliver-beacon/4.png)

`data`周りのセクションが若干シンボル難読化されているせいかエントロピーが高くなっています。この辺りに難読化データが入ってそうですね、わかんないけど。

## 静的解析
ビーコンのメイン関数に入るまでは`tak-skip.exe`で解析していこうと思います。
### Go language
SliverはGo言語製です。最初の実行処理周りはGo言語のバイナリを意識して解析する必要があります。
以下の様に最初は2回ほどJMPします。
※関数名などシンボルは自身で記載したものです。そのままリバーシングしても`sub_XXXXXX`のままなので、TryHarderしましょう。

![5](/images/sliver-beacon/5.png)

![6](/images/sliver-beacon/6.png)

その後、以下の様な処理に入ります。goroutineの呼出し前の処理です。

![7](/images/sliver-beacon/7.png)

ここで注目するのが以下の処理でしょうか。Intelフラグの確認処理ですね。
```
00464da0        if (temp0 != 0)
00464db8            if (temp1 == 0x756e6547 && temp3 == 0x49656e69 && temp2 == 0x6c65746e)
00464dba                isIntel = 1
```
この`0x756e6547`, `0x49656e69`, `0x6c65746e`は`GenuineIntel`の比較です。
また、`0x123`の書き込みも気になりますね。これはGo言語のTLSスロットでのメモリ書き込みのテストが行われています。

`GenuineIntel`の比較、`0x123`のテスト、最初のJMP命令というのも合わせてGo言語製バイナリの可能性が高いという判断が慣れてる人だとできたりするかなと思います。

以下の公式ドキュメントを参考にすると追いやすいです。

https://go.dev/src/runtime/asm_amd64.s

この関数の最後の処理を見てみるとGo言語特有の呼びだしが見えます。`newproc`からGoルーチンの呼出しが行われ、スタックに積まれている`mainPC`の指す`runtime.main`が`newproc`によって実行されます。

![8](/images/sliver-beacon/8.png)

![9](/images/sliver-beacon/9.png)

この流れは以下のブログが参考になると思われます。

https://engineers.ffri.jp/entry/2022/04/11/141131

`runtime.main`の中にはSliverのメイン関数があります。`main.main`がそれです。

![10](/images/sliver-beacon/10.png)

### Sliverのメイン関数
`main.main`に入ると、基本的に`--skip-symbols`オプションを指定したものと、そうでないものの違いはまだ特段ありません。

+ tak-skip.exe
![11](/images/sliver-beacon/11.png)

![12](/images/sliver-beacon/12.png)

+ tak.exe
![13](/images/sliver-beacon/13.png)

![14](/images/sliver-beacon/14.png)


違いがあるのは`008fe3e0`の関数（Init_Kernel32とか付けてるやつ）から呼び出される`008fe420`（tak-skip.exe）と`00e21fe0`（tak.exe）の関数です。Load_Kernel32の前にPlaneとかEncodeとか適当に名前つけ分けてます。

### シンボル難読化の解析
それぞれの中身を確認します。

+ tak-skip.exe
![15](/images/sliver-beacon/15.png)

+ tak.exe
![16](/images/sliver-beacon/16.png)

わぁ、全然違うや。
シンボル難読化されてないものは直で`kernel32.dll`の文字が見えます。おそらくDLLのロードだと思われます。難読化されてるほうはよくわからんバイトが並んでますね（コメントや関数名ですでにデコードや解析が済んでるのは悪しからず）。

ここからは難読化されてるほうの関数を追っていきます。

## 動的解析
### kernel32.dllの難読化
`00e22140`にある「decode_kernel32.dll」の中身を確認します。

![17](/images/sliver-beacon/17.png)

なんかよくわからんバイト列があります。なんやこれ。
アセンブリを読みます。

![18](/images/sliver-beacon/18.png)

スタックに積んでガチャガチャしてるのがわかるかと思います。ぱっと見でStack String Obfuscationっぽいですね。
こういうのは動的解析でStackのメモリ追ったほうが早いので動的解析します。

適当にRIPを対象の関数のaddress領域にセットして実行していきます。

![19](/images/sliver-beacon/19.png)

ガチャガチャ終わるとこにBP張って実行します。

![20](/images/sliver-beacon/20.png)

`kernel32.dll`の文字列が見えました。難読化解除成功です。

### Failed to loadの難読化
似たような難読化がロード関数にもあります。

![21](/images/sliver-beacon/21.png)

これもStack積んでガチャガチャしてたので同様に動的解析します。

![22](/images/sliver-beacon/22.png)

![23](/images/sliver-beacon/23.png)

`Failed to load`の文字列がStackメモリ上に見えます。これは難読化されてないものだと以下の様に見えます。

![24](/images/sliver-beacon/24.png)

### IsDebuggerPresentの難読化
最後に「Encode_Load_Kernel32_DLL」にあったバイト列の難読化も見てみます。
Stackガチャガチャしてたので同様に動的解析します。

![25](/images/sliver-beacon/25.png)

`IsDebuggerPresent`が見えます。アンチデバッグでよく使われるAPIですね。

こんな感じでStack String Obfuscationによって難読化されているバイト列がところどころにあります。
Stack Stringと言ってもロジック自体はバラバラで、Solverコード書くのが面倒そうです。面倒なのでやりません。許せサスケ。

# おわりに
Sliverのビーコンにおけるシンボル難読化手法をリバースエンジニアリングから見てきました。
Stack Stringを用いた難読化が主に使われていることがわかりました。
明日には忘れてそうな内容ですが、リバースエンジニアリングの参考になれば幸いです。