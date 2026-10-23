# PostgreSQL 17.10 原生 SM3 认证：本地源码分析与修改方案

> 历史分析稿（2026-10-22）：以下“尚未实现”等描述保留用于追溯当时方案。2026-10-23 已进入实现与测试；实际交付仅普通 SCRAM-SM3，不含 SM3-PLUS。最终行为、构建方式和验收以配套《Linux部署与Java验证.md》及交付验证记录为准。

分析日期：2026-10-22。仓库：[xiahuhu1/postgres-sm3](https://github.com/xiahuhu1/postgres-sm3)。本地目录：`/Users/xiahuhu/Documents/ChatGPT/devops/postgres-sm3/`。

## 1. 结论与本次边界

建议在现有 SCRAM 框架上新增 **`scram-sm3`** 认证家族，复用已有的消息交换、SASLprep、随机盐、PBKDF2、客户端证明和服务端签名流程。底层摘要、HMAC 和口令派生改用 SM3；同时完成服务端与 libpq 改造。

本方案中的 `scram-sm3`、`SCRAM-SM3` 和 `SCRAM-SM3-PLUS` 是拟新增到本分支的配置值和机制名，尚未实现。与 openGauss 使用相同散列算法，不代表自动兼容其驱动或线协议。

本次已下载 fork、建立本地工作分支、完成文件和函数级静态分析。当前变更仅为本方案文档；尚未实现 SM3、执行数据库构建或连接数据库。下述配置、机制名和测试步骤均为待实施方案。

| 基线项 | 本次核实结果 |
|---|---|
| origin | `https://github.com/xiahuhu1/postgres-sm3.git` |
| 版本标签 | `REL_17_10` |
| 基线提交 | `25c49f3a4a742ba283f5cc43cc7f1d361552e917`，提交说明 `Stamp 17.10.` |
| 本地工作分支 | `codex/sm3-17.10`，直接从上述标签创建 |
| 远端分支情况 | 有 `REL_17_STABLE`；未发现名为 `17.10` 的分支。本次使用固定 17.10 标签，而非稳定分支最新提交 |
| 下载范围 | `--depth 1 --branch REL_17_10` 浅克隆；当前 origin fetch refspec 只包含此标签，尚未获取完整历史 |
| 与此前发布源码比较 | 核对的 19 个核心文件逐字节一致；包括构建定义、密码原语、服务端认证、libpq 与 initdb，不代表比较了整个目录 |
| 构建状态 | 尚无生成的 `src/Makefile.global`；未验证生产服务器编译选项 |

本方案的文件行号对应该基线，后续编码后会移动。文件链接使用仓库相对路径，便于在 fork 中继续维护。

**成功标准：** 设置 `password_encryption='scram-sm3'` 后可以生成并保存 SM3 verifier；HBA 指定 `scram-sm3` 时，新 libpq 使用 SM3 完成客户端与服务端相互验证；错误口令、错配算法和受限客户端策略均可靠拒绝；原有 SHA256/MD5 行为通过回归。

## 2. 对外行为约定

| 项目 | 建议约定 |
|---|---|
| 口令生成配置 | `password_encryption = 'scram-sm3'` |
| HBA 方法 | `scram-sm3` |
| SASL 名称 | `SCRAM-SM3`、TLS 下的 `SCRAM-SM3-PLUS` |
| 保存格式 | `SCRAM-SM3$<iterations>:<base64 salt>$<base64 StoredKey>:<base64 ServerKey>` |
| 摘要与派生 | SM3、HMAC-SM3、PBKDF2-HMAC-SM3 |
| 密钥/摘要长度 | 32 字节；SM3 的分组长度为 64 字节 |
| 盐与 nonce | 复用现有 16 字节随机盐、18 字节随机 nonce 的生成流程 |
| 迭代配置 | 复用公开 GUC `scram_iterations`，首版沿用现有默认值 4096；上线值需测量认证成本后确定 |
| 全局默认值 | 继续使用原有 SHA256 默认值；管理员显式选择 SM3 |
| 第一阶段算法依赖 | 具有可用 `EVP_sm3()` 的 OpenSSL 构建；无能力时明确失败 |
| 系统表 | 继续保存到 `pg_authid.rolpassword` 的 text 字段 |

32 字节只是长度相同，不能复用 SHA256 的算法标识。口令数学关系为：

```text
P              = 沿用 PostgreSQL 的 SASLprep 及原始字节回退规则
SaltedPassword = PBKDF2-HMAC-SM3(P, salt, iterations, 32)
ClientKey      = HMAC-SM3(SaltedPassword, "Client Key")
StoredKey      = SM3(ClientKey)
ServerKey      = HMAC-SM3(SaltedPassword, "Server Key")
ClientSignature = HMAC-SM3(StoredKey, AuthMessage)
ClientProof     = ClientKey XOR ClientSignature
ServerSignature = HMAC-SM3(ServerKey, AuthMessage)
```

沿用现有 SCRAM 协议字段和 `AUTH_REQ_SASL` / `CONT` / `FIN` 消息，算法通过新机制名协商，不增加 `AUTH_REQ_SM3` 消息类型。

## 3. 当前调用链

### 3.1 设置和保存口令

```text
CREATE ROLE / ALTER ROLE
  src/backend/commands/user.c
  ├─ check_password_hook(... get_password_type(password) ...)
  ├─ plain_crypt_verify(..., "", ...)          检测预加密空口令
  └─ encrypt_password(Password_encryption, role, password)
       src/backend/libpq/crypt.c
       ├─ 已识别的 verifier：原样保存
       └─ 明文：pg_be_scram_build_secret()
            src/backend/libpq/auth-scram.c
            └─ scram_build_secret(hash_type, key_length, ...)
                 src/common/scram-common.c
                 └─ pg_hmac_* / pg_cryptohash_*
  → pg_authid.rolpassword
```

关键入口：[CREATE ROLE 调用](../../src/backend/commands/user.c)、[生成密码](../../src/backend/libpq/crypt.c)、[公共生成器](../../src/common/scram-common.c)。

### 3.2 服务端登录认证

```text
pg_hba.conf
  hba.c 解析方法 → HbaLine.auth_method
  → ClientAuthentication()                     auth.c
  → CheckPWChallengeAuth()
  → get_role_password()                        角色存在性/口令/过期检查
  → CheckSASLAuth(pg_be_sasl_mech, ...)
       auth-sasl.c
       ├─ get_mechanisms()                     公布机制名
       ├─ init()                               选机制、解析 verifier / mock
       └─ exchange()                           验证 proof、返回服务端签名
  → set_authn_id() / AuthenticationOk
```

关键入口：[HBA 解析](../../src/backend/libpq/hba.c)、[分派](../../src/backend/libpq/auth.c)、[通用 SASL](../../src/backend/libpq/auth-sasl.c)。

### 3.3 libpq 登录与修改口令

```text
pg_SASL_init()                  fe-auth.c
  → 选择机制 + 检查 require_auth / channel_binding
  → pg_scram_mech.init()        fe-auth-scram.c
  → SCRAM proof / 服务端签名校验

psql \password                 command.c
  → PQchangePassword()
  → PQencryptPasswordConn()
       algorithm=NULL → SHOW password_encryption
       → pg_fe_scram_build_secret()
       → ALTER USER ... PASSWORD '<verifier>'
```

关键入口：[客户端机制协商](../../src/interfaces/libpq/fe-auth.c)、[口令生成 API](../../src/interfaces/libpq/fe-auth.c)、[psql 入口](../../src/bin/psql/command.c)。

## 4. 公共算法层：复用与补齐

| 文件与定位 | 具体修改 |
|---|---|
| [cryptohash.h:19](../../src/include/common/cryptohash.h) | 在 `pg_cryptohash_type` 尾部追加 `PG_SM3`，保留已有枚举数值。 |
| [scram-common.h:19](../../src/include/common/scram-common.h) | 新增 `SCRAM_SM3_NAME`、`SCRAM_SM3_PLUS_NAME`、`SCRAM_SM3_KEY_LEN`。SM3/SHA256 均为 32 字节，现有最大缓冲区容量足够；常量表达式需明确涵盖两者。 |
| [cryptohash_openssl.c:178](../../src/common/cryptohash_openssl.c) | `pg_cryptohash_init()` 增加 `PG_SM3 → EVP_sm3()`；`:255` 的 final 分支补 32 字节目标缓冲区检查。 |
| [hmac_openssl.c:183](../../src/common/hmac_openssl.c) | `pg_hmac_init()` 增加 SM3；`:254` 的 final 分支补长度检查。 |
| [scram-common.c:209](../../src/common/scram-common.c) | `scram_build_secret()` 按 hash 选择前缀；修正 `:225` 的 SHA-only assert，以及 `:258` 长度计算、`:275` 格式化中的 SHA256 字面量。保留函数签名。 |
| [cryptohash.c:100](../../src/common/cryptohash.c) | 非 OpenSSL fallback 对不支持的 SM3 明确返回错误；同时检查 init/update/final 三处 switch。 |
| [hmac.c:93](../../src/common/hmac.c) | 非 OpenSSL fallback 明确拒绝 SM3；若以后实现内置 SM3，再补其 32 字节摘要/64 字节分组配置。 |

公共 `scram_SaltedPassword():38`、`scram_H():112`、`scram_ClientKey():142`、`scram_ServerKey():172` 已接收 `hash_type` 和 `key_length`，可直接复用。现有 PBKDF2 派生一个摘要长度，SM3 的 32 字节长度适合现有实现。

**关键问题：** 非 OpenSSL 的 `cryptohash.c` 相关 switch 没有兜底分支。仅向 enum 增加 `PG_SM3`，却不处理 fallback，会出现没有完成摘要计算但返回成功的路径。因此第一阶段即使只支持 OpenSSL，也必须修改/拦截 fallback，不能只改两个 OpenSSL 文件。

## 5. 密码类型、设置口令及备份恢复

| 文件与定位 | 具体修改 |
|---|---|
| [crypt.h:27](../../src/include/libpq/crypt.h) | `PasswordType` 尾部追加 `PASSWORD_TYPE_SCRAM_SM3`。 |
| [guc_tables.c:415](../../src/backend/utils/misc/guc_tables.c) | `password_encryption_options` 增加 `scram-sm3`；`:5093` 的默认值继续为 SHA256。按构建能力条件开放 SM3 配置值。 |
| [crypt.c:88](../../src/backend/libpq/crypt.c) | `get_password_type()` 根据 `parse_scram_secret()` 返回的 hash 区分 SHA256/SM3。当前只要 SCRAM 解析成功便返回 SHA256，这里必须修改。 |
| [crypt.c:115](../../src/backend/libpq/crypt.c) | `encrypt_password()` 增加 SM3 生成分支。已识别且受支持的 verifier 继续原样保存，防止恢复时被再次 hash。无 SM3 能力的构建遇到 SM3 设置/导入要给出明确错误。 |
| [crypt.c:223](../../src/backend/libpq/crypt.c) | `plain_crypt_verify()` 增加 SM3 case，共用 `scram_verify_plain_password()`。 |
| [auth-scram.c:472](../../src/backend/libpq/auth-scram.c) | 增加按算法生成 verifier 的内部实现。原 `pg_be_scram_build_secret(password)` 保持 SHA256 入口，SM3 分支调用新 helper；共享 SASLprep、盐和迭代处理。 |
| [auth-scram.c:589](../../src/backend/libpq/auth-scram.c) | `parse_scram_secret()` 接受两个前缀并返回正确 hash/key_length。继续校验 Base64 与两份 key 长度；新增 SM3 格式中的非正数、越界迭代参数不能被接受为有效 verifier。 |
| [scram.h:25](../../src/include/libpq/scram.h) | 增加必要 descriptor/helper 声明。 |

算法识别属于格式解析，不能把“运行环境暂不可用的 SM3”误识别为普通明文。格式解析与执行能力检查分开；实际设置、生成、认证时遇到不可用算法明确失败。

格式非法则是另一种情况：现有 `get_password_type()` 会把解析失败的字符串视为明文。为保留原有语义，形似 `SCRAM-SM3$...` 但格式非法的 SQL PASSWORD 字符串可按普通口令重新 hash；解析器拒绝将其当作 verifier，不等于 SQL 一定报错。测试要区分两者。若以后要求直接拒绝非法保留前缀，需要另行增加设置口令入口的校验。

关联行为必须验证：

- [user.c:435](../../src/backend/commands/user.c) 和 `:920` 使用 `plain_crypt_verify(..., "", ...)` 检测预加密空口令。漏掉 SM3 case 会破坏现有空口令保护。
- [passwordcheck.c:64](../../contrib/passwordcheck/passwordcheck.c) 已统一处理非明文类型，`:76` 委托 `plain_crypt_verify()` 检查“密码等于用户名”。修复通用路径后，该扩展通常只需补测试。
- [user.c:1447](../../src/backend/commands/user.c) 仅在角色改名时清除 MD5 口令。SM3 与 SHA256 一样不绑定角色名，应保留 verifier。
- [pg_authid.h:46](../../src/include/catalog/pg_authid.h) 已是 text，设计上不需要新增列、修改 catalog 结构或为了新格式重新初始化现有集群。
- [pg_dumpall.c:942](../../src/bin/pg_dump/pg_dumpall.c) 原样输出 `rolpassword`。恢复端需要正确识别 SM3 前缀，才能原样恢复并登录；dump 格式本身可继续使用。

## 6. 服务端 HBA 与 SASL 分派

| 文件与定位 | 具体修改 |
|---|---|
| [hba.h:25](../../src/include/libpq/hba.h) | 在枚举尾部追加 `uaSCRAMSM3` 并更新 `USER_AUTH_LAST`，避免移动现有数值。 |
| [hba.c:101](../../src/backend/libpq/hba.c) | 在 `UserAuthName[]` 对应位置追加 `scram-sm3`。现有静态断言要求名称表与 enum 数量对应。 |
| [hba.c:1718](../../src/backend/libpq/hba.c) | 解析 `scram-sm3`，设置 `uaSCRAMSM3`；无算法能力时输出明确配置错误。 |
| [auth.c:288](../../src/backend/libpq/auth.c) | 密码认证失败分支补 `uaSCRAMSM3`，保持通用 invalid-password SQLSTATE。 |
| [auth.c:598](../../src/backend/libpq/auth.c) | 新方法进入挑战认证。 |
| [auth.c:830](../../src/backend/libpq/auth.c) | 扩展 assert，并按 SM3 HBA 显式选择新 SM3 descriptor；保留 MD5→SHA256 的已有选择规则。 |
| [auth-scram.c:113](../../src/backend/libpq/auth-scram.c) | 新增 `pg_be_scram_sm3_mech`，通过少量包装函数复用初始化及已有 `scram_exchange()`。 |
| [auth-scram.c:202](../../src/backend/libpq/auth-scram.c) | 原 descriptor 仅公布 SHA256 家族；新 descriptor 仅公布 SM3 家族。TLS 下先 PLUS 再普通机制。 |
| [auth-scram.c:236](../../src/backend/libpq/auth-scram.c) | 初始化明确预期算法；客户端所选机制必须属于该 descriptor；存储 verifier 的算法必须匹配。 |
| [auth-scram.c:683](../../src/backend/libpq/auth-scram.c) | `mock_scram_secret()` 接收当前认证家族，生成相应参数，不能固定 SHA256。 |
| [auth-scram.c:1458](../../src/backend/libpq/auth-scram.c) | `scram_mock_salt()` 使用对应 hash；修正仅允许 SHA256 的 assert 和相应说明。 |

两个 descriptor 的方案只需少量包装层，不复制整份 SCRAM 实现。原因是 [get_mechanisms 接口](../../src/include/libpq/sasl.h) 只拿到 `Port`，不接收 verifier；让明确 HBA 家族决定可选机制，比同时公布两种算法再根据 verifier 拒绝更直接。

实现形状示意，非已提交补丁：

```c
/* 两个 get_mechanisms/init 包装入口，共享 exchange。 */
const pg_be_sasl_mech pg_be_scram_mech = {
    scram_sha256_get_mechanisms, scram_sha256_init, scram_exchange, /* ... */
};
const pg_be_sasl_mech pg_be_scram_sm3_mech = {
    scram_sm3_get_mechanisms, scram_sm3_init, scram_exchange, /* ... */
};

/* CheckPWChallengeAuth 内 */
if (port->hba->auth_method == uaSCRAMSM3)
    auth_result = CheckSASLAuth(&pg_be_scram_sm3_mech, port,
                               shadow_pass, logdetail);
else
    /* 原 MD5/SHA256 分派 */;
```

`auth-sasl.c` 的消息封装本身可直接复用。`verify_client_proof():1135`、`build_server_final_message():1399` 已使用状态中的算法和长度，原则上无需另写 SM3 proof 协议。保持已有常量时间比较和内存处理。

### 6.1 认证矩阵

以下“成功”均指口令正确且角色具备登录等必要权限。

| HBA 方法 | MD5 verifier | SHA256 verifier | SM3 verifier |
|---|---|---|---|
| `md5` | MD5 成功 | 保持原有 SHA256 自动选择 | 拒绝；按 SHA 家族模拟交换后失败 |
| `scram-sha-256` | 拒绝 | SHA256 成功 | 拒绝；按 SHA 家族模拟交换后失败 |
| `scram-sm3` | 拒绝；SM3 模拟交换 | 拒绝；SM3 模拟交换 | SM3 成功 |
| `password` | 原有校验 | 原有校验 | 可校验 SM3 verifier；仍是提交口令的认证方式 |

对于两类 SCRAM SASL 认证分支，不存在、无密码、密码过期、verifier 算法错配等情况均走所选家族的 doomed/mock 认证，向客户端返回通用错误。`password` 和 MD5 挑战分支保持各自现有流程。保留 [scram_exchange():438](../../src/backend/libpq/auth-scram.c) 先执行 proof 校验、再判断 doomed 的顺序。

## 7. libpq：机制、PLUS 与口令生成

| 文件与定位 | 具体修改 |
|---|---|
| [fe-auth.c:422](../../src/interfaces/libpq/fe-auth.c) | `pg_SASL_init()` 识别 SM3/SM3-PLUS；在算法许可范围内优先对应 PLUS；复用 `pg_scram_mech`，设置 `password_needed=true`。 |
| [fe-auth-scram.c:96](../../src/interfaces/libpq/fe-auth-scram.c) | `scram_init()` 按机制设置 `hash_type/key_length`。现有 state 已有这两个字段。 |
| [fe-auth-scram.c:154](../../src/interfaces/libpq/fe-auth-scram.c) | `scram_channel_bound()` 识别两个 PLUS 机制。 |
| [fe-auth-scram.c:345](../../src/interfaces/libpq/fe-auth-scram.c) | 首消息中 PLUS 的判断同步支持 SM3；`:450` 最终消息中的 channel binding 判断同步扩展。 |
| [fe-auth-scram.c:892](../../src/interfaces/libpq/fe-auth-scram.c) | 内部口令生成器补 hash/key 参数或新增薄包装；`:922` 不再一律传 SHA256。 |
| [fe-auth.h:28](../../src/interfaces/libpq/fe-auth.h) | 同步内部 helper 声明。 |
| [fe-auth.c:1276](../../src/interfaces/libpq/fe-auth.c) | `PQencryptPasswordConn()` 增加 `scram-sm3` 分支，显式算法和 NULL 跟随服务器两种路径都支持。公开 API 签名不变。 |

`PQchangePassword():1401` 和 psql 的 `\password` 会自然复用上述入口，不需再写 psql 侧加密逻辑。其 API 行为也必须实测，不能以“登录成功”代替“设置口令成功”。

迭代次数继续使用公开的 `scram_iterations` 及原有 ParameterStatus。现有 `scram_sha_256_iterations` C 变量/成员可暂保留名称，作为两种 SCRAM 生成器的输入；无需为改名扩大修改范围。登录挑战中的迭代数仍从 server-first-message 获取。

`.pgpass` 文件格式无需增加算法字段。SM3 选择分支需要保持 `password_needed` 标志，确保 `PQconnectionUsedPassword()` 以及 FDW/dblink 的现有口令检查继续正确工作。

### 7.1 必须同步修改 require_auth

[fe-connect.c:1426](../../src/interfaces/libpq/fe-connect.c) 把 `require_auth=scram-sha-256` 映射为整个 SASL 的 AuthRequest 位掩码，并注释“目前假设 SCRAM 是唯一 SASL 方法”。新增 SM3 后不能给两个算法复用这个掩码就结束：

- SHA256-only 的策略可能错误接受 SM3。
- `scram-sha-256,scram-sm3` 会被现有重复位判断误判为重复。
- `!scram-sha-256` 可能连 SM3 也一起禁掉。

具体方案：在 [libpq-int.h:488](../../src/interfaces/libpq/libpq-int.h) 对应内部连接状态增加独立 SASL 家族许可掩码，至少分 SHA256/SM3 两位。

1. `fe-connect.c` 解析正列表时从空集合增加，解析负列表时从全许可集合扣除；重复检查按具体家族进行。
2. 外层 AuthRequest 掩码只表示是否允许 SASL 消息交换；列表循环结束后，根据剩余家族统一推导 SASL/CONT/FIN 三个位，避免第二个家族再次触发现有外层重复检查。当至少一个 SASL 家族允许时，允许相应 SASL 消息。
3. `pg_SASL_init()` 在选择和发送 initial response 之前过滤具体机制，防止越过策略发送认证证明。
4. PLUS 与普通机制属于同一算法家族，`channel_binding` 单独约束绑定要求。
5. 新连接默认许可全部已支持家族；`connectOptions` 解析正/负策略时从 EMPTY/ALL 构建许可集合。已解析的策略须跨 `PQreset` 和多主机重试保留；每次尝试只清除已选机制、PLUS 和认证完成状态。不能在 `pqDropServerData()` 中把家族许可集合重置为 ALL，因为 `PQreset()` 不会重新解析连接选项。保留正负列表互斥、重复项、`none` 和认证未完成等已有规则。

### 7.2 客户端输入与机制优先级补充

[fe-auth-scram.c:671](../../src/interfaces/libpq/fe-auth-scram.c) 的 `read_server_first_message()` 当前把 `strtol()` 结果直接写入 `int`，仅检查尾部字符和小于 1，缺少 errno 和上限检查。引入 SM3 时应先用 `long` 临时变量校验转换成功及 `1..INT_MAX`，再写入状态；在进入 PBKDF2 前拒绝非法值。共享解析器的这一小处修正同时需要跑 SHA256 回归。

伪服务端输入至少覆盖 `i=0`、`i=-1`、`i=2147483648`、`i=4294967297`、超长十进制和含尾随字符的数值。超大值用例应证明没有执行昂贵的口令派生，不以等待计算超时判断成功。

[fe-auth.c:468](../../src/interfaces/libpq/fe-auth.c) 现有选择逻辑需要确定多家族优先级：先按 `require_auth` 过滤，再满足 `channel_binding`；PLUS 优先于 non-PLUS，在相同绑定级别保留服务端列表中首个可接受机制。不能复制两个 PLUS 判断，让后出现的机制覆盖先前选择。`channel_binding=disable` 时只选 non-PLUS，`require` 时必须有可用 PLUS。非 TLS 提供已识别 PLUS 的异常仍应明确拒绝。

测试需要伪服务端同时公布两个家族，交换列表顺序、夹杂未知机制，并断言被禁止的家族没有发送 SASL initial response。正常服务端的每条 HBA 仍只公布对应家族。

## 8. initdb 与构建能力

### 8.1 初始化集群

[initdb.c:97](../../src/bin/initdb/initdb.c) 和 `:119` 有独立 host/local 方法白名单，需要加入 SM3；[setup_config():1388](../../src/bin/initdb/initdb.c) 必须为选定 SM3 的初始化设置 `password_encryption=scram-sm3`；[check_need_password():2575](../../src/bin/initdb/initdb.c) 补入 SM3。

只改 HBA 白名单可能生成“SM3 HBA + SHA256 超级用户 verifier”的无法登录集群。同一角色只有一份 verifier；首版建议拒绝 host/local 同时要求不同 SCRAM 家族，或者 SM3 与 MD5 这种不能共同满足的初始化组合。SM3 配合 password/trust/peer 等方法按其实际语义处理，不用简单地拒绝一切混合配置。

### 8.2 功能检测与无能力失败

- [configure.ac:1345](../../configure.ac) 允许最低 OpenSSL 1.0.2，不能以启用了 OpenSSL 就认定有 SM3。
- 在现有 OpenSSL 功能检测区增加 `EVP_sm3` 编译/链接检测，生成 `HAVE_EVP_SM3` 或同等宏；同步 [meson.build:1388](../../meson.build)、生成的 `configure` 与配置头模板。沿用仓库既有生成工具版本。
- [src/common/Makefile:88](../../src/common/Makefile) 与 [src/common/meson.build:43](../../src/common/meson.build) 在 OpenSSL/内置实现间二选一，构建测试必须覆盖两个分支。
- 首版只在编译能力满足时开放 SM3 配置/机制；无 OpenSSL 或缺失 `EVP_sm3` 的版本继续可构建并使用原有算法，SM3 相关操作明确失败。
- 编译能力不等于运行时可用性。OpenSSL 3 的 SM3 实现来自 default provider，provider/属性策略也可能导致初始化失败；必须检查摘要与 HMAC 初始化返回值并终止操作，禁止自动回退 SHA256。[OpenSSL SM3 文档](https://docs.openssl.org/3.0/man7/EVP_MD-SM3/)

`EVP_sm3()` 的摘要长度为 256 位。[OpenSSL EVP_sm3 文档](https://docs.openssl.org/1.1.1/man3/EVP_sm3/)

### 8.3 PLUS 与 TLS 的边界

[be-secure-openssl.c:1555](../../src/backend/libpq/be-secure-openssl.c) 与 [fe-secure-openssl.c:362](../../src/interfaces/libpq/fe-secure-openssl.c) 按证书签名算法计算 `tls-server-end-point`，对 MD5/SHA1 证书摘要使用 SHA256。SM3-PLUS 复用这套绑定语义，不能随意把绑定证书摘要改成 SM3。

SM3 口令认证、TLS 传输算法、证书签名算法属于不同配置范围。实现本方案不会自动把 TLS 或证书链整体替换为国密。

## 9. 测试计划与执行顺序

| 测试入口 | 必测内容 |
|---|---|
| 小型 C 算法测试模块/harness，当前树未见现成 test_crypto 模块 | SM3 固定向量及跨分组输入；HMAC 短/长密钥；PBKDF2 迭代 1/2/4096；固定盐 verifier；31 字节目标缓冲区拒绝。使用独立 OpenSSL API/固定向量交叉验证，避免仅服务端与客户端共同算错也测试通过。 |
| [regress/sql/password.sql](../../src/test/regress/sql/password.sql) 及对应 expected | 保持 MD5/SHA256 原有回归。SM3 的配置值、verifier 格式、预生成 verifier、空口令、迭代数、非法格式及改名用例优先放进能力分支明确的 TAP，避免固定输出因构建差异分叉。 |
| [authentication/t/001_password.pl](../../src/test/authentication/t/001_password.pl) | 完整认证矩阵；错误/NULL/过期/不存在角色；方法日志和 SYSTEM_USER；客户端生成口令；require_auth 正负、双算法、重复、none、重连及未完成握手。 |
| [authentication/t/002_saslprep.pl](../../src/test/authentication/t/002_saslprep.pl) | 对 SM3 运行已有 Unicode/SASLprep 规则及非法字节回退测试。 |
| [ssl/t/002_scram.pl](../../src/test/ssl/t/002_scram.pl) | SM3 下 channel_binding=disable/prefer/require；PLUS 成功、无 TLS require 失败、错误绑定、降级、与 require_auth 的组合。 |
| [initdb/t/001_initdb.pl](../../src/bin/initdb/t/001_initdb.pl) | `-A scram-sm3` 初始化后能用超级用户登录；缺口令拒绝；混合配置策略；缺算法能力错误。 |
| [libpq/test](../../src/interfaces/libpq/test) | 显式/默认 PQencryptPasswordConn、PQchangePassword；错误服务端签名、错误/跨家族机制、非 TLS 提供 PLUS 等负向协议行为。 |
| globals dump/restore、FDW/dblink、客户端交叉版本 | dump/restore 后 verifier 不变且能登录；保留 --no-role-passwords；新 libpq 连接原版 SHA256 服务；旧 libpq 连接 SM3 明确失败；动态库实际加载正确。 |
| 构建矩阵 | 有 SM3 的 OpenSSL；无 OpenSSL；有 OpenSSL 但缺 SM3；运行时 SM3 不可用。原有算法均不能受影响。 |

实现后，在独立构建目录配置 `--with-ssl=openssl --enable-tap-tests --enable-cassert` 并完成构建，再执行以下已有目标；这批命令本轮未执行：

```sh
make -C src/test/regress check-tests TESTS=password
make -C src/test/authentication check
PG_TEST_EXTRA=ssl make -C src/test/ssl check
make -C src/bin/initdb check
make -C src/interfaces/libpq check
```

需要相应编译依赖及 TAP Perl 模块；TLS 用例需要测试证书。补充算法/负向协议用例后，再按改动范围运行完整回归。尚无实现，当前不能声称这些测试已经通过。

### 9.1 可选构建与测试注册

SM3 配置值按编译能力开放，而 `regress/sql/password.sql` 使用固定 expected 文件。因此不能无条件追加 SM3 SQL 并让无 SM3 构建对同一输出做比较。建议使用 [PostgreSQL::Test::Utils::check_pg_config():758](../../src/test/perl/PostgreSQL/Test/Utils.pm) 检测新增的 `HAVE_EVP_SM3`，在 TAP 内明确区分能力分支；不支持分支仍覆盖 GUC/HBA/库接口明确拒绝。若采用 SQL 回归，则必须设计对应 expected 选择，不能依赖跳过错误。

libpq 的 TAP 脚本目录是 `src/interfaces/libpq/t/`，C helper 在 `src/interfaces/libpq/test/`。新增脚本需要登记 [libpq/meson.build:109](../../src/interfaces/libpq/meson.build) 的显式测试列表；新 helper 需要同时登记 [test/Makefile:17](../../src/interfaces/libpq/test/Makefile) 和 [test/meson.build:24](../../src/interfaces/libpq/test/meson.build)。其他新增算法测试模块也须在 Make/Meson 两套入口注册。

现有 `libpq_testclient` 仅支持 `--ssl`，不足以直接测试 `PQreset()`、`PQencryptPasswordConn()` 和 `PQchangePassword()`。应补必要 API/协议 helper，并验证重连之后算法许可策略仍生效。

## 10. 建议补丁拆分

1. **公共算法和格式：** SM3 枚举、构建能力探测、摘要/HMAC、公共 verifier builder、独立算法测试。先证明每个原语正确及无能力时明确失败。
2. **服务端：** 密码类型/解析/生成、HBA、双 descriptor、mock、明文验证关联路径及 SQL/认证矩阵测试。
3. **客户端：** libpq 协商/PLUS、require_auth 家族约束、客户端生成口令及正负协议测试。完成此步才形成可用的双端认证闭环。
4. **初始化和交付：** initdb、dump/restore、交叉版本、FDW/dblink、构建矩阵，以及必要文档和配置样例。

配置/文档需同步的位置包括 `src/backend/utils/misc/postgresql.conf.sample`、`src/backend/libpq/pg_hba.conf.sample`、`doc/src/sgml/client-auth.sgml`、`doc/src/sgml/config.sgml`、`doc/src/sgml/libpq.sgml`、`doc/src/sgml/protocol.sgml`、`doc/src/sgml/catalogs.sgml`、`doc/src/sgml/ref/initdb.sgml`。重点说明新算法值、认证矩阵、客户端要求、require_auth、PLUS 语义和 verifier 格式。文档章节按实际落点更新，不做无关重排。

## 11. 部署与迁移约束

首批建议只对测试角色和限定 HBA 规则开启 SM3，不立即切换所有账号：

```conf
# 以下仅在上述补丁完成并验证后生效。
# postgresql.conf
password_encryption = 'scram-sm3'

# pg_hba.conf，替换为实际数据库/角色/网段。
hostssl  appdb  sm3_test  10.20.30.0/24  scram-sm3
```

使用改造后的 psql，通过 `\password sm3_test` 重新设置口令，随后建立全新连接验证。切换生成算法不会改写已有 verifier，MD5/SHA256 verifier 也不能直接转换为 SM3；同一角色当前只有一份口令，重置为 SM3 后原 SHA256 认证路径不能同时继续使用同一 verifier。

升级客户端应早于切换对应业务账号的 verifier。JDBC、纯 Python/Go 驱动、代理若自行实现认证，需要各自适配；使用 libpq 的应用还要核对实际加载的库。openGauss 驱动不能仅凭“都叫 SM3”视为兼容。

物理复制/恢复会带上角色 verifier，所有可能接管登录的数据库节点都应具有同样的 SM3 支持；复制连接自身如果使用 SM3，也依赖改造后的客户端认证能力。只在主库改造不足以完成主备切换验收。

普通备份可保留新 verifier，但回退到未改造版本后，这些账号不能继续用 SM3 登录。回退认证需要重新设置受支持算法的口令或恢复已有的适当认证凭据；不能从 SM3 verifier 还原旧 verifier。现有数据目录的二进制兼容和扩展 ABI 仍须结合最终补丁及实际构建验证；“无需修改 catalog”不等于已验证可直接替换生产二进制。

本方案只界定技术实现。是否满足具体密评要求，需要依据采用的密码实现、产品/模块要求和认证部署范围判断，不能仅凭新机制名认定通过。

## 12. 本次核对记录

- `configure.ac:20`：`AC_INIT([PostgreSQL], [17.10], ...)`。
- 本地 `HEAD` 与 `REL_17_10` 均指向 `25c49f3a4a742ba283f5cc43cc7f1d361552e917`，工作分支 `codex/sm3-17.10`；未发现仓库内的 `AGENTS.md`。
- 当前 `password_encryption_options` 只有 MD5、SHA256；当前 `get_password_type()` 对所有成功解析的 SCRAM 统一返回 SHA256。
- 当前通用 SCRAM 原语、服务端/客户端状态已含 hash/key 参数；但命名、builder、parser、mock、PLUS 判断和策略仍存在 SHA256 固定逻辑。
- 已核对上述 make 测试目标存在；未运行构建和测试。

关键文件 SHA256，用于后续核对分析基线：

```text
configure.ac
4f910e7099606400933b4190ba69aa77e78bb53331925b676c59a6d125fe4649
src/common/scram-common.c
da809e92d3bbfdcd0eaebef53def09f328e5d0ce29875755e5ef930259076de8
src/backend/libpq/auth-scram.c
ed6c6087acc382be6ae9195a638d1a4646d4e04c7fc7070cc432315eba08914e
src/interfaces/libpq/fe-auth-scram.c
4fa33af2b03f80254468190f2847d122bf49fb832f46fa7e64463c4e978f304a
src/backend/libpq/crypt.c
f75fa0a7c87b703c326ab02b1c505626fc419c916db7b2d9ccc90fca5004edab
```


## 13. 首个实施里程碑与本机准备

### 13.1 M1：算法能力和公共 verifier

第一批补丁先完成算法和格式，达到可独立验证的边界；服务端 GUC/HBA 开放与登录闭环属于后续批次。

| 文件组 | 第一批要完成的内容 |
|---|---|
| `configure.ac`、`configure`、`src/include/pg_config.h.in`、根 `meson.build` | 检测并导出 `EVP_sm3` 能力，处理有 OpenSSL 但无该函数的构建 |
| `src/include/common/cryptohash.h`、`src/include/common/scram-common.h` | 尾部追加算法枚举；添加独立名称、摘要长度常量 |
| `src/common/cryptohash_openssl.c`、`hmac_openssl.c` | SM3 初始化、输出长度和 OpenSSL 错误处理 |
| `src/common/cryptohash.c`、`hmac.c` | 无算法能力时明确失败，防止未知枚举走成功路径 |
| `src/common/scram-common.c` | 两种算法共用已有派生流程，按 hash 输出准确前缀 |
| 必要测试及 Make/Meson 登记 | 独立固定向量、HMAC、PBKDF2、固定盐 verifier、缓冲区错误、旧算法回归和能力缺失分支 |

M1 验收：SM3 摘要/HMAC/PBKDF2 与独立向量或 OpenSSL API 一致；同一盐和迭代数下 verifier 完全可复现；SHA256 输出不变；无 OpenSSL 构建仍通过原有算法检查，SM3 请求明确失败。此时不把“公共函数可用”描述为“用户已能用 SM3 登录”。

M2/M3 完成服务端和 libpq 后，再按第 6.1 节矩阵完成双端登录闭环；M4 补齐 initdb、备份恢复、交叉驱动和交付文档。

### 13.2 本机工具快照

以下为 2026-10-22 的本机只读检查结果，不是生产运行环境信息：

- `git`、Clang、Make、Perl、pkg-config 可用。
- pkg-config 发现 OpenSSL `3.6.3`；尚未执行 `EVP_sm3` 的编译/运行探测。
- Bison `2.3`、Flex `2.6.4` 可用。
- 当前 PATH 未找到 Autoconf、Meson、Ninja。`configure.ac:22` 要求生成工具为 Autoconf `2.69`；仓库已有 `configure`，但修改构建检测后需要以合适工具重新生成。
- 当前 pkg-config 搜索路径未找到 `icu-uc`。这不能证明整台机器未安装 ICU。隔离开发构建可显式使用 `--without-icu`，生产构建则应核对所需 ICU 功能及原有编译配置。

本次没有安装工具或改动全局依赖，也没有创建数据库实例。后续构建宜放在独立目录，防止生成文件混入源码变更。
