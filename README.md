# SymmetricEncryption

Format to using different versions of the file encryptor:

v1.0 commands:\
**Encryption** - java FileEncryptor1 enc "directoryName/plaintext.txt" "outputDirectoryName/outputFileName.enc"\
**Decryption** - java FileEncryptor1 dec ((base 64 encoded key)) ((base 64 IV)) "directoryName/cipher.enc" "outputDirectoryName/outputFileName.txt"

v2.0 commands:\
**Encryption** - java FileEncryptor2 enc ((base 64 encoded key)) "directoryName/plaintext.txt" "outputDirectoryName/outputFileName.enc"\
**Decryption** - java FileEncryptor2 dec ((base 64 encoded key)) "directoryName/cipher.enc" "outputDirectoryName/outputFileName.txt"

v3.0 commands:\
**Encryption** - java FileEncryptor3 enc "my password" "directoryName/plaintext.txt" "outputDirectoryName/outputFileName.enc"\
**Decryption** - java FileEncryptor3 dec "my password" "directoryName/cipher.enc" "outputDirectoryName/outputFileName.txt"

v4.0 commands:\
**Encryption** - java FileEncryptor4 enc AlgorithmName KeySize "my password" "directoryName/plaintext.txt" "outputDirectoryName/outputFileName.enc"\
**Decryption** - java FileEncryptor4 dec "my password" "directoryName/cipher.enc" "outputDirectoryName/outputFileName.txt"\
**Cipher Info** - java FileEncryptor4 info "directoryName/cipher.enc"
