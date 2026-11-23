# pairwise-ssrf-redirect-guard

## 领域

安全

## 主题

SSRF 跳转防护

## 说明

解析后校验、CIDR 判定与二次解析比对。

初始状态下 `security/ssrf_redirect_guard.py` 中所有函数抛出 `NotImplementedError`，测试全部失败。
修复实现后运行：

```bash
python -m pytest -q
```

期望全部通过。
