#define OBYTES 48
#define PBYTES 96
#define PRIV_KEY_LEN OBYTES      //Privatekey len in bytes
#define PUB_KEY_LEN 8*PBYTES     //Publickey len in bytes

int SISig_P751_Keygen(unsigned char *PrivateKey, unsigned char *PublicKey);

int SISig_P751_Sign(char *msg, unsigned char *signature,
        unsigned char *PrivateKey, unsigned char *PublicKey);

int SISig_P751_Verify(char *msg, unsigned char *sig, unsigned char *PublicKey);
