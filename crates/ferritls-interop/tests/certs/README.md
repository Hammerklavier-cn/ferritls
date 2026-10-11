# 测试证书链（openssl 生成，仅测试用）

全部证书为**本地生成的测试专用链**，SAN 仅 `DNS:localhost`，私钥无任
何真实安全性。目录只提交证书与 leaf 私钥（PKCS#8 DER）；CA 私钥、
CSR、.srl 序号文件不留存（丢弃后无法延签，重新生成整链即可）。

统一 profile（与仓库首批 P-256/RSA 链一致）：

- 有效期 7300 天；
- root：`CA:TRUE, pathlen:1`（critical）+ `keyCertSign, cRLSign`
  （critical），自签；
- intermediate：`CA:TRUE, pathlen:0`（critical）+ `keyCertSign`
  （critical）；
- leaf：`CN=localhost`、`CA:FALSE`、`digitalSignature`、
  `extendedKeyUsage=serverAuth`、`subjectAltName=DNS:localhost`。

| 链 | 文件前缀 | 驱动的验证路径 |
|---|---|---|
| P-256 | `root`/`int`/`leaf` | ECDSA P-256/SHA-256（webpki.rs `webpki_chain_*`） |
| RSA-2048 | `rsa_root`/`rsa_int`/`rsa_leaf` | PKCS#1 v1.5 与 PSS × SHA-256/384/512（`webpki_rsa_*`） |
| Ed25519 | `ed25519_root`/`ed25519_int`/`ed25519_leaf` | Ed25519（`webpki_ed25519_*`） |
| P-384 | `p384_root`/`p384_int`/`p384_leaf` | ECDSA P-384/SHA-384（`webpki_p384_*`） |
| 客户端链 | `client_root`/`client_leaf` | mTLS 客户端认证（mtls.rs；EKU clientAuth） |
| 无关根 | `root2.pem` | 「不可信根」负例 |

客户端链 profile：`client_root` 自签（`CA:TRUE, pathlen:0` +
`keyCertSign`）；`client_leaf` 为 `CN=ferritls test client`、`CA:FALSE`、
`digitalSignature`、`extendedKeyUsage=clientAuth`（**无 SAN**——客户端
证书不做主机名校验）。leaf 由 client_root 直接签发（隔一层中间）。
「不可信客户端证书」负例复用 Ed25519 服务器链（issuer 不在
client_root 信任锚内），不另发证书。

## 再生成命令（OpenSSL 3.x）

以 Ed25519 链为例（P-384 把 `genpkey -algorithm ed25519` 换成
`genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -pkeyopt
ec_param_enc:named_curve`，文件名前缀同步替换；P-256/RSA 同理）：

```bash
# root（自签）；摘要必须与曲线配对（P-256→sha256、P-384→sha384）：
# openssl x509/req 的默认摘要是 sha256，P-384 链忘配对会被 webpki 以
# UnsupportedSignatureAlgorithmForPublicKeyContext 拒绝
openssl genpkey -algorithm ed25519 -out /tmp/ed_root.key.pem
openssl req -x509 -new -key /tmp/ed_root.key.pem -out ed25519_root.pem \
  -days 7300 -subj "/CN=ferritls test ed25519 root" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# intermediate（root 签发）
openssl genpkey -algorithm ed25519 -out /tmp/ed_int.key.pem
openssl req -new -key /tmp/ed_int.key.pem \
  -subj "/CN=ferritls test ed25519 intermediate" -out /tmp/ed_int.csr
printf "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign\n" > /tmp/ed_int.ext
openssl x509 -req -in /tmp/ed_int.csr -CA ed25519_root.pem \
  -CAkey /tmp/ed_root.key.pem -CAcreateserial -days 7300 \
  -extfile /tmp/ed_int.ext -out ed25519_int.pem

# leaf（int 签发）+ leaf 私钥 DER
openssl genpkey -algorithm ed25519 -out /tmp/ed_leaf.key.pem
openssl req -new -key /tmp/ed_leaf.key.pem -subj "/CN=localhost" -out /tmp/ed_leaf.csr
printf "subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n" > /tmp/ed_leaf.ext
openssl x509 -req -in /tmp/ed_leaf.csr -CA ed25519_int.pem \
  -CAkey /tmp/ed_int.key.pem -CAcreateserial -days 7300 \
  -extfile /tmp/ed_leaf.ext -out ed25519_leaf.pem
# 注意必须显式转 PKCS#8：`openssl pkey -outform DER` 对 EC 会输出
# 传统 SEC1 格式（Ed25519 无 SEC1 才侥幸正确），而测试按
# PrivateKeyDer::Pkcs8 解析。
openssl pkcs8 -topk8 -nocrypt -in /tmp/ed_leaf.key.pem -outform DER \
  -out ed25519_leaf.key.der

rm -f *.srl   # 序号文件不入库
```

客户端链（mTLS，P-256，PemObject 按 PrivateKeyDer::Pkcs8 解析）：

```bash
# client_root（自签；只发叶子，pathlen:0 即可）
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -pkeyopt ec_param_enc:named_curve -out /tmp/cl_root.key.pem
openssl req -x509 -new -key /tmp/cl_root.key.pem -out client_root.pem \
  -days 7300 -subj "/CN=ferritls test client root" -sha256 \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign"

# client_leaf（client_root 直签，EKU clientAuth，无 SAN）
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -pkeyopt ec_param_enc:named_curve -out /tmp/cl_leaf.key.pem
openssl req -new -key /tmp/cl_leaf.key.pem -subj "/CN=ferritls test client" \
  -out /tmp/cl_leaf.csr
printf "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n" > /tmp/cl_leaf.ext
openssl x509 -req -in /tmp/cl_leaf.csr -CA client_root.pem \
  -CAkey /tmp/cl_root.key.pem -CAcreateserial -days 7300 \
  -extfile /tmp/cl_leaf.ext -sha256 -out client_leaf.pem
# 同上：EC 私钥必须显式转 PKCS#8
openssl pkcs8 -topk8 -nocrypt -in /tmp/cl_leaf.key.pem -outform DER \
  -out client_leaf.key.der

rm -f *.srl
```

链完整性自检：

```bash
openssl verify -CAfile ed25519_root.pem -untrusted ed25519_int.pem ed25519_leaf.pem
```
