# 公共密码算法向量

在源目录和独立构建目录完成 `configure --with-ssl=openssl`、`make` 后运行，`PG_SM3_SRC` 和 `PG_SM3_BUILD` 替换为实际绝对路径：

```sh
PG_SM3_SRC=/path/to/postgres-sm3
PG_SM3_BUILD=/path/to/build
cc -DFRONTEND \
  -I"$PG_SM3_BUILD/src/include" -I"$PG_SM3_SRC/src/include" \
  "$PG_SM3_SRC/doc/sm3/tests/crypto-vectors.c" \
  "$PG_SM3_BUILD/src/common/libpgcommon.a" \
  "$PG_SM3_BUILD/src/port/libpgport.a" \
  $(pkg-config --cflags --libs openssl) -o /tmp/pg-sm3-crypto-vectors
/tmp/pg-sm3-crypto-vectors
```

摘要包含标准的 `abc` 和 64 字节 `abcd` 向量。HMAC/PBKDF2 及固定盐校验值通过 Python `hashlib`/`hmac` 的独立 OpenSSL 实现生成，未使用 PostgreSQL 公共 SCRAM 实现生成期望值：

```python
import hashlib, hmac
print(hmac.new(b'key', b'The quick brown fox jumps over the lazy dog', 'sm3').hexdigest())
for rounds in (1, 2, 4096):
    print(rounds, hashlib.pbkdf2_hmac('sm3', b'password', b'salt', rounds, 32).hex())
```

`SM3_EXPECT_UNSUPPORTED` 编译选项用于测试不支持 SM3 的后端。使用非 OpenSSL 构建的静态库时，添加 `-DSM3_EXPECT_UNSUPPORTED`，移除 `pkg-config openssl` 参数：应通过显式失败测试，SHA256 校验值仍然保持一致。OpenSSL 库存在但 `EVP_sm3` 不存在的构建也执行相同测试。该程序返回非零表示测试失败。

也可在已有 OpenSSL 构建中直接替换摘要/HMAC 对象，单独验证内置 fallback 实现的拒绝路径：

```sh
cc -DFRONTEND -DSM3_EXPECT_UNSUPPORTED \
  -I"$PG_SM3_BUILD/src/include" -I"$PG_SM3_SRC/src/include" \
  "$PG_SM3_SRC/doc/sm3/tests/crypto-vectors.c" \
  "$PG_SM3_SRC/src/common/cryptohash.c" \
  "$PG_SM3_SRC/src/common/hmac.c" \
  "$PG_SM3_SRC/src/common/md5.c" \
  "$PG_SM3_SRC/src/common/sha1.c" \
  "$PG_SM3_SRC/src/common/sha2.c" \
  "$PG_SM3_BUILD/src/common/libpgcommon.a" \
  "$PG_SM3_BUILD/src/port/libpgport.a" -o /tmp/pg-sm3-fallback-vectors
/tmp/pg-sm3-fallback-vectors
```

这只验证 fallback 对象，不代表完成了整套非 OpenSSL 数据库构建。
