---
title: "【Offsec】OSWE合格体験記"
emoji: "🕷️"
type: "idea" # tech: 技術記事 / idea: アイデア
topics: [Security, Offsec, OSWE, Web]
published: false
---

# はじめに
本記事はOffsecが提供する「Offensive Security Web Expert（OSWE）」に合格した体験記です。

この試験はみんな体験記書いてるので、だいぶ簡単に書きます。

![1](/images/oswe/1.png)

# OSWEとは
OSWEは、Offsecが提供する[WEB-300](https://www.offsec.com/courses/web-300/)というトレーニングコースを受講し、試験に合格することで得られる資格です。

XSSやSQLiなどのWebアプリケーションの脆弱性をソースコードから発見し、その脆弱性を連鎖させて全自動でRCEまで動作するエクスプロイトを作成するスキルまで身につけることができます。いわゆるホワイトボックス診断ですね。具体的には上記リンクのOffsec公式サイトや[シラバス](https://www.offsec.com/documentation/awae-syllabus.pdf)をご覧ください。

# 筆者の受講前のスキル感
自分はSOC業務に従事しており、たまにペネトレーションテスト、たまにマルウェア解析といった業務を行っております。資格としては以下のものを持っています。

+ Zero2Automated
+ OSED（OffSec Exploit Developer）
+ OSEP（Offensive Security Experienced Penetration Tester）
+ OSCP（Offensive Security Certified Professional）
+ CARTP（Certified by Altered Security Red Team Professional for Azure）
+ 情報処理安全確保支援士

Web Exploitに関してはあまり業務で深く触れない内容のため、HTBなどのLinuxマシンでExploitをやって力をつけていたぐらいです。正直Web分野はCTFなどを含めてかなり苦手意識がありました。

ただ開始時点では、[Web Security Academy](https://portswigger.net/web-security)の内容について全体の40％ほどを完了しており、基礎は身についていたかなと思います。

# 学習スケジュール
[OSEDをPwnedした](https://zenn.dev/taksecbe/articles/osed-success)後すぐに学習にとりかかりました。
| 時期 | 内容 |
| --- | --- |
| 4月 | テキスト、動画を見てました。<br>知らないことが多く、かなり苦戦しました。|
| 5月 | まだテキストから抜け出せていませんでした。Webの知識が貧弱過ぎる。|
| 6月前半 | Challenge Labsをひたすらやってました。<br/>HTBでいえばMidやHardベースの題材が多い印象でそこまで苦戦はしませんでした。1つを除いて。|
| 6月後半 | Challenge Labsの残りを進めつつ、Web Security AcademyでSQLiやXSSなど弱点補強を行っていました。50％ほどに進められました。|
| 7月 | 試験 |

HTBだとRCEに繋がる脆弱性を利用することが多く、そこに繋がるまでの脆弱性のExploitは疎かにしていたので、補強するのに苦戦しました。

# 実技試験について
## 概要
実技試験では問題が2つ用意され、各侵害対象についてAuth Bypassで35点、RCEで15点配分となります。
合格最低点の85点を取るには、2つの問題のうち1つを完遂し、もう1つでAuth Bypassをする必要があります。つまり、Auth Bypassは全て実施する必要があります。

この実技試験が47時間45分、実技試験終了後24時間以内にレポート提出が必要です。
特徴的なのは、ExploitをRCEまで完全自動で行うScriptを作成する必要がある点です。Auth Bypassまでしかできなかったものも対象です。
詳細は[ガイドライン](https://help.offsec.com/hc/en-us/articles/360046869951-WEB-300-Advanced-Web-Attacks-and-Exploitation-OSWE-Exam-Guide)をご覧ください。

## 制約事項
基本的にKaliのローカルへのファイル転送は禁止です。デバック環境に用意されているコードサーバーを利用していく形になるので注意してください。
ただし、SSHでの接続でデバック環境へのコマンドは実行可能です。脆弱性の当たりを付けるために`grep`コマンドを用意しておくと便利でしょう。

詳細は[FAQ](https://help.offsec.com/hc/en-us/articles/360046418812-OSWE-Exam-FAQ)をご覧ください。

## 実際の実技試験中
何故かOffsecの試験では毎回Challenge Labsの問題より難しいものを引くのはどうしてでしょうか？体感HTBのHard相当の問題を2つ引いた気がします。

１日目に2つのAuth Bypassが完了し、そこからRCEは1つは終盤に完了しましたが、残り１つが中々刺さらず、これしかないだろという脆弱性をひたすらコネコネしてました。ラビットホールなのかどうかはわかりませんが、終盤までRCEが出来ずにヒヤヒヤしてました。

しんどいよ徹夜。

## レポート
レポートは仮眠を取ってから書き始めました。以下のToolを利用しました。

https://github.com/Syslifters/sysreptor

## 合格通知
合格通知はレポート提出の約1日後に来ました。今回もギリギリの点数だったので、自信はありませんでしたが、無事合格できて良かった。

# 参考になった書籍やサイト、問題など
ここでは参考になった書籍やブログを紹介したいと思います。

## 書籍
### 実践 Webペネトレーションテスト
これはいい本です。最近のWeb技術まで拾ってくれるので実践的な内容が多いのでは。

https://www.oreilly.co.jp/books/9784814401253/

### 体系的に学ぶ 安全なWebアプリケーションの作り方 第2版
これは必須ではないでしょうか？

https://www.sbcr.jp/product/4797393163/

### ハッキングAPI
APIもやるのでこれも読んでおいたらいいかも。

https://www.oreilly.co.jp/books/9784814400249/

### サイバーセキュリティプログラミング 第2版
Exploit開発でPythonを利用したので、読んだらいいかも。

https://www.oreilly.co.jp/books/9784873119731/

## ブログ
### 体験記
一部抜粋です。お世話になりました。

https://zenn.dev/conamikan/articles/65cd74822feb8b

https://speakerdeck.com/y0d3n/kowakunaioswe

https://p-0.me/b/p/620/

https://www.mbsd.jp/research/20240605/offensive-security-web-expert-oswe/

## 参考問題
### Web Security Academy
Webの中でも特にSQLiが苦手だったのでそこを集中的に取り組みました。
その中でも以下の問題は自動でExploitできるようにコードを一度作成してみることをお勧めします。また、便利な[チートシート](https://portswigger.net/web-security/sql-injection/cheat-sheet)もあるので参考にしてみてはいかがでしょうか。

https://portswigger.net/web-security/sql-injection/blind/lab-time-delays

### HTB
現時点でActiveなマシンなので詳細は語りませんが、「CCTV」のEasyマシンは参考になりました。
今のうちにやっておくといいかもです。

https://app.hackthebox.com/machines/CCTV

# 最後に
OSWEは個人的に300台の中で一番苦手分野で、難しい試験でした。

ただ、この試験を通じてある程度のWeb Exploitの知識が付き、SQLiやXSSなどの脆弱性のExploitを克服し、Exploitを自動化するスキルも身につけることができました。今後の業務に活かしていきたいと思います。

あー、バリむずかった。よくやった俺。