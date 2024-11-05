package com.github.wegoo.cain.asn1.gm;

import com.github.wegoo.cain.asn1.ASN1BitString;
import com.github.wegoo.cain.asn1.ASN1EncodableVector;
import com.github.wegoo.cain.asn1.ASN1Object;
import com.github.wegoo.cain.asn1.ASN1Primitive;
import com.github.wegoo.cain.asn1.ASN1Sequence;
import com.github.wegoo.cain.asn1.DERSequence;
import com.github.wegoo.cain.asn1.x509.AlgorithmIdentifier;

//GMT-0009
public class SM2EnvelopedKey extends ASN1Object {
  //算法标识
  private AlgorithmIdentifier algorithm;
  //对称密钥密文
  private SM2Cipher symEncryptedKey;
  //SM2PublicKey ::= BIT STRING
  private ASN1BitString publicKey;
  //SM2算法私钥密文
  private ASN1BitString sm2EncryptedPrivateKey;

  public static SM2EnvelopedKey getInstance(Object o){
    if (o instanceof SM2EnvelopedKey) {
      return (SM2EnvelopedKey)o;
    } else if (o != null) {
      return new SM2EnvelopedKey(ASN1Sequence.getInstance(o));
    }
    return null;
  }

  private SM2EnvelopedKey(ASN1Sequence seq){
    algorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
    symEncryptedKey = SM2Cipher.getInstance(seq.getObjectAt(1));
    publicKey = ASN1BitString.getInstance(seq.getObjectAt(2));
    sm2EncryptedPrivateKey = ASN1BitString.getInstance(seq.getObjectAt(3));
  }


  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector vector = new ASN1EncodableVector();
    vector.add(algorithm);
    vector.add(symEncryptedKey);
    vector.add(publicKey);
    vector.add(sm2EncryptedPrivateKey);
    return new DERSequence(vector);
  }
}
