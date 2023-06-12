---
layout: post
title: Linux Kernel Module Signing
tags: [Linux]
---

最近又回去看 kernel module 的東西，所以弄了一個用 UEFI 開機的 vm，結果在編譯好要 `insmod` 的時候

```bash
nick@nick-ubuntu-vm:~/coding/test-kernel$ sudo insmod ./test-kernel.ko
[sudo] password for nick: 
insmod: ERROR: could not insert module ./test-kernel.ko: Key was rejected by service
```

查了一下，由於 UEFI Secure Boot 的關係，自己寫的 kernel module 也要簽名，因此這篇文章就是要來弄這件事

## 1. 建立簽名用的公私鑰對 Machine Owner Key (MOK)
首先使用 `openssl` 建立 DER 格式的公私鑰對，把輸出檔案放在 `~/.keys` 資料夾

在 `~/.keys` 資料夾底下執行

```bash
openssl req -new -x509 -newkey rsa:2048 -nodes -days 36500 -outform DER -keyout MOK.priv -out MOK.der
```

填入適當的資訊後就可以建立一對 MOK

> `kmodsign` 好像只支援 RSA，在測試中 ED25519 是不能使用的

## 2. 註冊 MOK 到 firmware (的 shim) 中
使用 `mokutil` 註冊剛剛建立的 MOK 的公鑰

```bash
sudo mokutil --import MOK.der
```

> 在這個過程中會需要輸入密碼，這個密碼在等一下的註冊過程會用到

完成後重新開機，重新開機後會進入 MOK 管理的畫面

<img src="https://nickchen120235.s3.tebi.io/f2194760.png" style="display: block; margin: auto" />

按任意鍵後會進入選單，選擇「Enroll MOK」

<img src="https://nickchen120235.s3.tebi.io/493c3667.png" style="display: block; margin: auto" />

進來之後可以確認要加入的 MOK 是不是剛才建立的那個
<div style="display: flex; margin-bottom: 20px">
    <img src="https://nickchen120235.s3.tebi.io/52044107.png" style="padding: 0 8px" />
    <img src="https://nickchen120235.s3.tebi.io/771a91b9.png" style="padding: 0 8px" />
</div>

確認完之後按任意鍵回到 Enroll MOK 的畫面，選擇「Continue」後選擇「Yes」確認加入 MOK

<img src="https://nickchen120235.s3.tebi.io/25153404.png" style="display: block; margin: auto" />

這個時候輸入剛剛在 `mokutil` import 的時候設定的密碼

<img src="https://nickchen120235.s3.tebi.io/c64c27d6.png" style="display: block; margin: auto" />

完成後選擇「Reboot」重新開機

<img src="https://nickchen120235.s3.tebi.io/5eb9a095.png" style="display: block; margin: auto" />

---

重新開機後可以執行

```bash
sudo mokutil --list-enrolled
```

確認剛剛的 MOK 是不是有成功加入，可以透過「Issuer」等欄位確認資訊

```bash
nick@nick-ubuntu-vm:~$ sudo mokutil --list-enrolled
[key 1]

...

[key 3]
SHA1 Fingerprint: 04:dd:cb:a3:64:cd:ba:ca:eb:f7:56:bf:01:8b:ef:60:32:18:54:aa
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            7a:04:4f:7e:67:91:5f:a5:70:f2:65:4b:49:26:a1:13:26:07:69:9c
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=TW, L=Taipei, O=Nick, CN=Secure Boot Signing/emailAddress=example@example.com
        Validity
            Not Before: Jun  5 15:07:42 2023 GMT
            Not After : May 12 15:07:42 2123 GMT
        Subject: C=TW, L=Taipei, O=Nick, CN=Secure Boot Signing/emailAddress=example@example.com
        
...
```

## 3. 使用 MOK 進行簽名

簽名使用 `kmodsign`，使用時同時需要公鑰與私鑰，格式如下，通常使用 `sha512` 作為 hash 的演算法

```bash
kmodsign <hash algorithm> <私鑰> <公鑰> <模組.ko>
```

執行後會在 module 的最後加入簽名的資訊，可以使用 `hexdump` 檢查

```bash
nick@nick-ubuntu-vm:~/coding/test-kernel$ kmodsign sha512 ~/.keys/MOK.priv ~/.keys/MOK.der test-kernel.ko
nick@nick-ubuntu-vm:~/coding/test-kernel$ hd ./test-kernel.ko | tail -n 5
0000f2c0  55 4a 5a a7 f0 26 29 1b  ef 90 1f 4b bc 18 05 d4  |UJZ..&)....K....|
0000f2d0  7f 1f 82 b7 61 e8 7e 00  00 02 00 00 00 00 00 00  |....a.~.........|
0000f2e0  00 01 cf 7e 4d 6f 64 75  6c 65 20 73 69 67 6e 61  |...~Module signa|
0000f2f0  74 75 72 65 20 61 70 70  65 6e 64 65 64 7e 0a     |ture appended~.|
0000f2ff
```

最後再 `insmod` 就會成功

### 參考
- [https://ubuntu.com/blog/how-to-sign-things-for-secure-boot](https://ubuntu.com/blog/how-to-sign-things-for-secure-boot)
