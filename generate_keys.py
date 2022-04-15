import rsa

fpriv = open('new_priv.pem','wb')
fpub = open('new_public.pem','wb')
print('Generating keys')
(public, private) = rsa.newkeys(256, accurate=1)
fpub.write(public._save_pkcs1_pem())
fpriv.write(private._save_pkcs1_pem())
fpub.close()
fpriv.close()