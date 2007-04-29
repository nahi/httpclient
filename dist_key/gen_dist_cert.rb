require 'openssl'
include OpenSSL

keypair = PKey::RSA.new(File.read("keypair.pem"))

now = Time.now
cert = X509::Certificate.new
name = X509::Name.parse("/C=JP/O=ctor.org/OU=Development/CN=http-access2")
cert.subject = cert.issuer = X509::Name.new(name)
cert.not_before = now
cert.not_after = now + 2 * 365 * 24 * 60 * 60
cert.public_key = keypair.public_key
cert.serial = 0x0
cert.version = 2 # X509v3

key_usage = ["cRLSign", "keyCertSign"]
ef = X509::ExtensionFactory.new
ef.subject_certificate = cert
ef.issuer_certificate = cert # we needed subjectKeyInfo inside, now we have it
ext1 = ef.create_extension("basicConstraints","CA:TRUE", true)
ext2 = ef.create_extension("nsComment","Ruby/OpenSSL Generated Certificate")
ext3 = ef.create_extension("subjectKeyIdentifier", "hash")
ext4 = ef.create_extension("keyUsage", key_usage.join(","), true)
cert.extensions = [ext1, ext2, ext3, ext4]
ext0 = ef.create_extension("authorityKeyIdentifier", "keyid:always,issuer:always")
cert.add_extension(ext0)
cert.sign(keypair, Digest::SHA1.new)

print cert.to_pem
