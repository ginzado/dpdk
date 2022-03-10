# ginzado-pseudowire

以下の 2 つの方法で L2 延伸をするためのもの。

* Ethernet over Ethernet
* Ethernet over IPv6

DL 側ポートから受け取ったフレームを上記のいずれかの方法でエンキャップして UL 側ポートから出す。
UL 側ポートから受け取ったフレームを上記のいずれかの方法でデキャップして DL 側ポートから出す。

エンキャップ時に UL 側ポートの MTU を超える時はフラグメントしてから出す。UL 側ポートでフラグメントされたものを受け取った時はリアセンブルしてから DL 側ポートから出す。

ソースコードは `app/ginzado-pseudowire/ginzado_pseudowire.c` 。

## エンキャップとデキャップ

エンキャップ時のヘッダはそれぞれ以下のようになる。

### Ethernet over Ethernet

| ヘッダ                        | サイズ   |
|:-----------------------------|--------:|
| 外側 Ethernet ヘッダ          | 14 byte |
| フラグメント制御データ(後述)     |  2 byte |
| オリジナル　Ethernet フレーム |         |

外側 Ethernet ヘッダの EtherType はオレオレ値 0x96fc (仮)。

### Ethernet over IPv6

| ヘッダ                        | サイズ   |
|:-----------------------------|--------:|
| 外側 Ethernet ヘッダ          | 14 byte |
| 外側 IPv6 ヘッダ              | 40 byte |
| フラグメント制御データ(後述)     |  2 byte |
| オリジナル　Ethernet フレーム |         |

外側 IPv6 ヘッダのプロトコル番号はオレオレ値 0xfc (仮)。

## フラグメント制御データ

フラグメントしてない時は 0 を埋める。

フラグメントした時は以下の値を埋める。

### 前半の場合

| フラグメントフラグ(1 bit) | 後半フラグ(1 bit) | ID(14 bit) |
|----------------:|----------:|:---:|
|               1 |         0 | リアセンブル時の判別用ID値|

### 後半の場合

| フラグメントフラグ(1 bit) | 後半フラグ(1 bit) | ID(14 bit) |
|----------------:|----------:|:---:|
|               1 |         1 | リアセンブル時の判別用ID値|

リアセンブル時の判別用ID値には前半と後半で同じ値を埋める。この値から対応する前後半か否か(要するに元々同じフレームだったか否か)を判断する。この値はフラグメント時にその都度インクリメントする。

## 使い方

### ビルド

```
$ git clone (このリポジトリの URL)
$ cd dpdk
$ meson build
$ cd build
$ ninja
```

### DPDK の設定

hugepages を使うのでそのための設定。

```
# mkdir /dev/hugepages # 必要に応じて
# echo 64 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
# modprobe uio_pci_generic
```

まずはポートの情報を調べる。

```
$ sudo path/to/dpdk/dpdk-devbind.py
Network devices using kernel driver
===================================
0000:02:01.0 '82545EM Gigabit Ethernet Controller (Copper) 100f' if=ens33 drv=e1000 unused=vfio-pci *Active*
0000:03:00.0 'VMXNET3 Ethernet Controller 07b0' if=ens160 drv=vmxnet3 unused=vfio-pci 
0000:0b:00.0 'VMXNET3 Ethernet Controller 07b0' if=ens192 drv=vmxnet3 unused=vfio-pci 

...
```

例として 0000:03:00.0 と 0000:0b:00.0 を DPDK で使う場合以下のコマンドを実行。

```
$ sudo path/to/dpdk/usertools/dpdk-devbind.py -u 0000:03:00.0
$ sudo path/to/dpdk/usertools/dpdk-devbind.py -u 0000:0b:00.0
$ sudo path/to/dpdk/usertools/dpdk-devbind.py -b uio_pci_generic 0000:03:00.0
$ sudo path/to/dpdk/usertools/dpdk-devbind.py -b uio_pci_generic 0000:0b:00.0
```

### 設定ファイルの作成

Ethernet over Ethernet の場合以下のような設定ファイルを作成する。

```
eth           # mode
000c2979489d  # dstmac
```

dstmac には対向機器の MAC アドレスをコロンなしで埋める。

Ethernet over IPv6 の場合以下のような設定ファイルを作成する。

```
ip6           # mode
20010db80000000200000000000196fc # dstaddr
20010db80000000100000000000096fc # srcaddr
```

基本的には Ethernet over Ethernet と同様。

dstaddr には対向機器の IPv6 アドレスをコロンなしで埋める。
srcaddr には自身の IPv6 アドレスをコロンなしで埋める。

### 実行

```
$ sudo path/to/dpdk/build/app/dpdk-ginzado-pseudowire -l 1-3 -- --config path/to/config.ip6
```

上記例で `-l 1-3` の部分は DPDK のループ処理をどのコアで実行するかを指定する。
この例の環境は 0 から 3 までの 4 コアがあるので後半の 1 から 3 までのコアを使ってループを回すことになる。

`ginzado-pseudowire` は

* UL ポートから受け取ったフレームを処理するループ(lcore_ul 関数内)
* DL ポートから受け取ったフレームを処理するループ(lcore_dl 関数内)
* 破棄するフレームなどを処理したりその他全ての処理をするためのループ(lcore_main 関数内)

の 3 つのループを走らせるので必ず 3 つ指定する。
