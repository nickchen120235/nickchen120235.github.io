---
layout: post
title: Twitter Syndication API 筆記
tags: [Notes]
excerpt_separator: <!--more-->
---

Twitter, WTF?
<!--more-->

> 1. 因為前端 API 被爬爆所以弄了資料 API
> 2. 有人賺不夠所以推出 100鎂/月的 read access API，前端 API 又被爬爆
> 3. 設置流量限制，課金玩家才有資格看推特 ← 現在在這

總之 Twitter 又差點把自己搞砸，
還好[有人在 GitHub 上](https://github.com/JustAnotherArchivist/snscrape/issues/996#issuecomment-1615937362)
提到 embedded tweet 用的 `syndication.twitter.com` API 還沒被處理，
雖然一次只能抓 20 篇推文，不過對於我的 use case 來說應該是足夠的，
本文主要記錄 `/srv/timeline-profile/screen-name/[screen-name]` 這個 endpoint

## 在開始之前
所有的資料都是從 [https://publish.twitter.com/](https://publish.twitter.com/) 來的，
所以如果要找跟推文有關的 endpoint 也可以利用這個網站 + Developer Tools 去看

## JSON 資料
Embedded 的版本一樣是用 react (更正確來說是 Next.js) 去作渲染，
不過要渲染的資料已經透過 Server-Side Rendering 放在 `<script id="__NEXT_DATA__">`裡面了，
所以在 Python 下可以使用 `requests` + `BeautifulSoup` 直接把資料 dump 出來，
不用搭配 Selenium 去渲染再爬

主要的資料在 `data['props']['pageProps']` (假設 `script` 標籤的資料是 `data`) 底下，
其中最重要的是

|key|data|type|
|:-:|:-:|:-:|
|latest_tweet_id|最新推文的 ID|string|
|timeline|推文們|object|

> 有的時候 `latest_tweet_id` 會不見，不知道為什麼，目前可以確定的是 `latest_tweet_id` 不見的時候 `timeline` 會沒有推文

### `timeline`
這個物件只有一個 key `entries`，裡面會保存最新 20 篇的推文資料

每一個 entry 有以下的 key

```
dict_keys(['type', 'entry_id', 'sort_index', 'content'])
```

其中最重要的是 `content` 這個 key 底下的 `tweet`，主要的內容整理如下

> 說時遲那時快，在我寫到這裡的時候 syndication API 就掛了，way to go Elon

|key|data|type|
|:-:|:-:|:-:|
|id_str|推文 ID|string|
|entities|hashtag、圖片、連結、@使用者等資訊|object|
|full_text|推文全文|string|
|permalink|推文連結 (去掉 https://twitter.com)|string|
|user|推文者的資訊|object|
|quoted_status|引用的推文|`tweet` object|
|quoted_status_permalink.expanded|引用推文的 url|string|
|retweeted_status|轉推的推文|`tweet` object|
|retweeted_status_permalink.expanded|轉推推文的 url|string|

#### `entities.media[]`

重要的只有 `media_url_https`，提供直接連結到圖片的 url，可以用於 discord、ptt 等直接開圖
