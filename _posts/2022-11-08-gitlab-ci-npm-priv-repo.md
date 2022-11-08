---
layout: post
title: GitLab CI + npm Private Repo
tags: [Notes]
---
學到新招

在 GitLab CI 中，npm 安裝的 package 走 `git+ssh` 時，可以用

```yaml
before_script:
  - git config --global url."https://gitlab-ci-token:${CI_JOB_TOKEN}@gitlab.example.com/group/repo.git".insteadOf ssh://git@gitlab.example.com:group/repo.git
```

繞過去

## Reference
- [https://stackoverflow.com/a/49552383](https://stackoverflow.com/a/49552383)
- [https://gist.github.com/taoyuan/bfa3ff87e4b5611b5cbe?permalink_comment_id=3892150#gistcomment-3892150](https://gist.github.com/taoyuan/bfa3ff87e4b5611b5cbe?permalink_comment_id=3892150#gistcomment-3892150)
