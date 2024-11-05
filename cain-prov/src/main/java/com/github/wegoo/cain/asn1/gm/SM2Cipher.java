package com.github.wegoo.cain.asn1.gm;

import com.github.wegoo.cain.asn1.ASN1Encodable;
import com.github.wegoo.cain.asn1.ASN1EncodableVector;
import com.github.wegoo.cain.asn1.ASN1Integer;
import com.github.wegoo.cain.asn1.ASN1Object;
import com.github.wegoo.cain.asn1.ASN1OctetString;
import com.github.wegoo.cain.asn1.ASN1Primitive;
import com.github.wegoo.cain.asn1.ASN1Sequence;
import com.github.wegoo.cain.asn1.DERSequence;

/**
 * SM2Cipher ::= SEQUENCE {
 *    x INTEGER, --c1 x
 *    y INTEGER, --c1 y
 *    hash octet string,  --c3
 *    cipherText octet string  --c2 }
 */

public class SM2Cipher extends ASN1Object {

  private ASN1Integer x;
  private ASN1Integer y;
  private ASN1OctetString hash;
  private ASN1OctetString cipherText;

  public static SM2Cipher getInstance(Object o) {
    if (o instanceof SM2Cipher) {
      return (SM2Cipher) o;
    } else if (o != null) {
      return new SM2Cipher(ASN1Sequence.getInstance(o));
    }
    return null;
  }

  private SM2Cipher(ASN1Sequence seq) {
    this.x = (ASN1Integer) seq.getObjectAt(0);
    this.y = (ASN1Integer) seq.getObjectAt(1);
    this.hash = (ASN1OctetString) seq.getObjectAt(2);
    this.cipherText = (ASN1OctetString) seq.getObjectAt(3);
  }


  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector vector = new ASN1EncodableVector();
    vector.add(x);
    vector.add(y);
    vector.add(hash);
    vector.add(cipherText);
    return new DERSequence(vector);
  }
}
