---
layout: post
title: Google Cloud Function with GitHub Action CI/CD筆記
tags: [Notes]
---
~~GitHub Actions，從入門到自動入墳~~

最近想把手邊的一組API改寫成Google Cloud Function (搭配Google Firestore)，然後之前模擬面試有被提到要去了解CI/CD，所以就有了這篇筆記

參考Repo：[https://github.com/nickchen120235/google-cloud-cicd](https://github.com/nickchen120235/google-cloud-cicd)

## Workflow檔案
<script src="https://gist.github.com/nickchen120235/90c8e9fb1d35eb84ccb153ee56d56f59.js"></script>

1. `on`決定這個workflow什麼時候觸發
2. `jobs`的下一個key決定不同job在GitHub Actions的頁面顯示什麼名字
3. `runs-on`~~無腦`ubuntu-latest`就對了~~，除非有特殊需求
4. `permissions`參考[https://github.com/google-github-actions/auth](https://github.com/google-github-actions/auth)
5. `steps`列出每一步要做什麼
6. **任何不希望被看到的東西要放在`secrets`底下！！！** (Repo/Settings/Secutiry/Secrets/Actions)
   - Google Cloud Project ID
   - Google Cloud Authentication JSON

## Google Cloud相關設定
### Authentication
參考：[https://github.com/google-github-actions/auth](https://github.com/google-github-actions/auth)
1. Google Cloud Console/IAM與管理/服務帳戶 (Service Accounts) 建立服務帳戶
2. 「將專案存取權授予這個服務帳戶」：Cloud Functions管理員
3. 「完成」
4. 在管理頁面點進剛剛建的帳戶 -> 金鑰 -> 新增金鑰 -> 建立新的金鑰 -> 把json檔案的內容貼到GitHub那邊放secrets的地方
5. 給權限：開啟Google Cloud Shell -> (設定當前專案`gcloud config set project <PROJECT_ID>`) -> `gcloud iam service-accounts add-iam-policy-binding <SERVICE_ACCOUNT> --member=serviceAccount:<CICD_ACCOUNT>  --role=roles/iam.serviceAccountUser`
    - `SERVICE_ACCOUNT`填你在**IAM與管理**看到的以`appspot.gserviceaccount.com`結尾的帳號
    - `CICD_ACCOUNT`填在第一步建立的帳號

GitHub Actions的部份只要注意`with/credentials_json`有設好就好

### Deploy
沒什麼好寫的，參考[https://github.com/google-github-actions/deploy-cloud-functions](https://github.com/google-github-actions/deploy-cloud-functions)即可

~~唯一值得注意的是`region`不要寫錯~~

還有Functions deploy完預設是只有authenticated的使用者才可以存取，要開給所有人的話參考[https://cloud.google.com/functions/docs/securing/managing-access-iam#after_deployment](https://cloud.google.com/functions/docs/securing/managing-access-iam#after_deployment)

## NPM packages？
可以使用`require`去引用其他的package，但是要記得把`package.json`跟`package-lock.json`一起複製到`build/`（或到時候deploy的資料夾），這樣在Google Cloud Functions那端deploy的時候就不會有問題

## `us.artifacts.<PROJECT_ID>.appspot.com`？
~~要客家就要把東西清乾淨~~

想說換區了應該不會再被收錢了吧，結果還是有消費紀錄，打開Google Cloud Console一看才發現有一個multi-region的bucket出現在那邊~~，有人在搞？~~

餵狗之後才發現說那是Cloud Build留下來的痕跡，由於Cloud Functions在佈署的時候會使用Cloud Build，所以就會留下一堆container的cache

手動清除是沒有問題，可是既然都用CI/CD了，當然這個部份也要自動化

Google有提供一個[Setup Google Cloud SDK的GitHub Action](https://github.com/google-github-actions/setup-gcloud)，**在Authentication**完之後使用就可以使用`gcloud`、`gsutil`這兩個CLI工具，在佈署完後加上一個step去清就可以了

也就是像這樣的`action.yml`

<script src="https://gist.github.com/nickchen120235/ff0e043572b609134a37a47f4bb5b0b2.js"></script>

btw如果Service Account是自訂的話，要多給一個`storage.buckets.delete`權限

## Environment Variables
如果想要使用環境變數的話，在佈署的時候加一個選項`env_vars`就好

Bonus：要把npm的`npm_package_version`弄出去的話，把它加到GitHub Actions的`$GITHUB_ENV`就好，[詳細寫法](https://github.com/nickchen120235/google-cloud-cicd-ts/blob/master/.github/workflows/main.yml#L55)

## 參考資料
- [gcloud iam service-accounts add-iam-policy-binding \| Google Cloud CLI Documentation](https://cloud.google.com/sdk/gcloud/reference/iam/service-accounts/add-iam-policy-binding)
- [Using IAM to Authorize Access \| Cloud Functions Documentation \| Google Cloud](https://cloud.google.com/functions/docs/securing/managing-access-iam#after_deployment)
- [google-github-actions/auth](https://github.com/google-github-actions/auth)
- [google-github-actions/deploy-cloud-functions](https://github.com/google-github-actions/deploy-cloud-functions)
- [Can I delete container images from Google Cloud Storage artifacts bucket? - Stack Overflow](https://stackoverflow.com/questions/59937542/can-i-delete-container-images-from-google-cloud-storage-artifacts-bucket)