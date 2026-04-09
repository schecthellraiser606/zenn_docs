---
title: "【Offsec】OSED合格体験記"
emoji: "🦾"
type: "idea" # tech: 技術記事 / idea: アイデア
topics: [Security, Offsec, OSED, バイナリ解析, Pwn]
published: true
---

# はじめに
本記事はOffsecが提供する「OffSec Exploit Developer（OSED）」に合格した体験記です。

だいぶ簡単に書きます。

![1](/images/osed/1.png)

# OSEDとは
OSEDは、Offsecが提供する[EXP-301](https://www.offsec.com/courses/exp-301/)というトレーニングコースを受講し、試験に合格することで得られる資格です。

主にWindows x86の公開されたPortがあるサービスに対してNW越しにユーザランドでの攻撃を行うためのスキルを身につけることができます。具体的には上記リンクのOffsec公式サイトや[シラバス](https://www.offsec.com/documentation/EXP301-syllabus.pdf)をご覧ください。

# 筆者の受講前のスキル感
自分はSOC業務に従事しており、たまにペネトレーションテスト、たまにマルウェア解析といった業務を行っております。資格としては以下のものを持っています。

+ Zero2Automated
+ OSEP（Offensive Security Experienced Penetration Tester）
+ OSCP（Offensive Security Certified Professional）
+ CARTP（Certified by Altered Security Red Team Professional for Azure）
+ 情報処理安全確保支援士
+ MS認定 SC-200（Security Operations Analyst Associate）

またバイナリエクスプロイトという文脈に関しては、Linuxのx64のCTFをちょこっと手を出している感じでヒープエクスプロイトまではチャレンジできるくらいのスキル感です。といってもFSOPは苦手だし、カーネルエクスプロイトはさっぱりです。`__free_hook`恋しいです。

# 学習スケジュール
1月ごろに学習を開始しました。詳細は以下です。
| 時期 | 内容 |
| --- | --- |
| 1月前半 | テキスト、動画を見てました。<br>CTFのPwnとマルウェア解析で培った内容が多く、ざっと流し読みしました。|
| 1月後半 | ExtraMilesを進めてました。テキストの内容が大半なので、１つを除いてさっとクリアできると思います。<br>心臓の弱い方だったので、その1つは心臓破裂しました。|
| 2月 | Challenge Labsをひたすらやってました。|
| 3月 | Challenge Labsの3つめが難しく、引き続きやってました。<br>また、OSED練習問題としてGitHubに上がっている問題（後述）もやってました。|
| 4月 | 試験 |

ほぼWinDBGとIDA漬けの日々で辛かったです。x64dbgとBinaryNinjaが恋しく、仕事で強制的に触る機会を設けてました。

# 実技試験について
## 概要
実技試験では問題が3つ用意され、合格最低点を取るには2問完遂する必要があります。
この実技試験が47時間45分、実技試験終了後24時間以内にレポート提出が必要です。
詳細は[ガイドライン](https://help.offsec.com/hc/en-us/articles/360052977212-EXP-301-Windows-User-Mode-Exploit-Development-OSED-Exam-Guide)をご覧ください。

## 制約事項
他のOffsecの試験比べてこの試験は制約事項が多く、試験ポータルを繰り返し読むことになると思います。この制約事項を意識しておかないと、折角問題を解いても採点されない可能性があるので注意が必要です。

事前に自分の方で確認しておいた方がいい事項を特記事項として並べておきます。
+ IDA Freeのみ利用可能
  + 逆コンパイラは利用不可
+ WinDBGのみ利用可能
+ 基本的にはファイルのローカルへの転送は禁止

逆にOKだった事項も記載します。
+ pwntoolsなどのExploit開発用ライブラリの利用
+ [IDA Free 9.2](https://hex-rays.com/blog/open-sourcing-ida-sdk)から利用できるようになったSDKの活用
  + IDCが利用できるようになってるので、IDA Freeでの解析が捗ります。
  + これは直接Offsecに問い合わせてFreeと互換性があれば許可されるとのことでした。

詳細は[FAQ](https://help.offsec.com/hc/en-us/articles/360053660531-OSED-Exam-FAQ)を読み漁ってください。

## 実際の実技試験中
Challenge Labsの問題たちよりだいぶ難しい問題が出題されており、血の涙を流しながら解いていました。

1，2問目は大体1日目の終わり、明け方に完遂できました（血涙）。3問目はその次の日の明け方になっても解けず、3問目は捨て、終了3時間前に1，2問目を完璧にすることに注力しました（血涙）。

徹夜は辛かったですが、なんとか合格できて良かったです。

## レポート
レポートは仮眠を取ってから書き始めました。以下のToolを利用しました。

https://github.com/Syslifters/sysreptor

## 合格通知
合格通知はレポート提出の約3日後に来ました。正直ギリギリの点数だったので、自信はありませんでしたが、無事合格できて良かったです（いやマジで）。

解けた問題についてもシラバスやChallenge Labsだけだと厳しいなと思う場面もあり、日々の学習の積み重ねが大事だなと痛感しました。

# 利用するといいTool
## pwntools
バリバリ活躍してもらいました。`asm`でPythonにアセンブリを組み込め。Exploitコードと同じファイルで確認できるのは便利ですね。また、`recvuntil`でメモリリークを受ける際も便利ですね。

https://github.com/gallopsled/pwntools

## osed-scripts
以下に利用すると便利なスクリプトが大体落ちてます。

https://github.com/epi052/osed-scripts

## code_caver
メモリの保護状態を確認するのに便利なツールです。

https://github.com/nop-tech/code_caver

## ropper
デバックが出来るラボマシンにProxyなどを用いてインストールする必要があります。`search`コマンドは便利ですよね。`search % %, esp`などでスタックポインタ弄れるガジェットを探せるのはとても便利でした。`badbytes`コマンドで不要ガジェット弾けるのもいいですね。

https://github.com/sashs/Ropper

## win-x86-shellcoder
おまどんさんのShellcode Generatorです。シェルコードを生成するToolを自作するときに参考になります。結局自分で作成したほうがいい場面もあるのでこのToolは参考程度に自作ToolでShellcodeを生成する仕組みは整えておきましょう。

https://github.com/ommadawn46/win-x86-shellcoder

# 参考になった書籍やサイト、問題など
ここでは参考になった書籍やブログを紹介したいと思います。

正直この知識が無かったら落ちてました。

## 書籍
### Windowsセキュリティインターナル
出版マジで感謝します。

https://www.oreilly.co.jp/books/9784814401062/

### インサイド Windows 第7版 上下巻 
これ買ってて良かった。

https://amzn.asia/d/0fcSbtSZ

https://amzn.asia/d/0gaOm4Oz

### 初めてのマルウェア解析
IDA Freeで解析すると思いますが、その目的でこの本はいいと思います。

https://www.oreilly.co.jp//books/9784873119298/

また、正直VirtualAllocなどシラバスなどで出てくるWindows APIの勉強だけでは実技対策として不十分だと思うので、実際にマルウェアが利用するようなAPIを学んでおくといいと思います。そのAPI達をバイナリとして侵害対象に叩き込むことを意識すると実際に攻撃者が用いるシェルコードを読んでおくのがとても参考になります。

ここら辺はマルウェア解析、または自作C2などでいい感じに鍛えられるのかな？と思います。
自身はマルウェア解析の方で研鑽していました。

## ブログ
### 体験記
ここは読んでおいた方がいいです。

https://blog.nflabs.jp/entry/2023/12/21/093000

https://tan.hatenadiary.jp/entry/2023/10/30/020524

## 参考問題
どの問題も試験本番よりは易しい内容だったので、`vulnserver`以外はある程度詰まることなく瞬殺できるレベル感だと望ましいです。
### signatus
https://github.com/bmdyy/signatus
### quote_db
https://github.com/bmdyy/quote_db
### vulnserver
https://github.com/stephenbradshaw/vulnserver
### vulnbins
https://github.com/xct/vulnbins
### RemoteApp
https://github.com/Sh3lldon/RemoteApp

### SECCON CTF
Pwnで16進数周りやレジストリの扱いに慣れておいた方がいいと思います。ROPを組むときに変な感じで勘違いして上手くいかないということは減らせると思います。

また、Pythonを利用するときにpwntoolsのバイナリいじいじだけでは厳しいこともあると思うのでrev問題で暗号を軽く表現できるパッケージ、並列演算、多項式処理などは表現できるようにするパッケージは触っておくといいと思います。

https://github.com/SECCON

# 最後に
OSEDはとても難しい試験でしたが、バイナリの世界にのめり込んだいい経験でした。また、今までの低レイヤ知識を存分に叩き込めたこともあり、集大成感がある試験でした。

目を血走らせガンギマリ脳筋プレイで粘り強くデバッカカタカタしてました。（多分おかしい問題引いただけな気がしてますが...）

Pwnは楽しいぜ！！！！