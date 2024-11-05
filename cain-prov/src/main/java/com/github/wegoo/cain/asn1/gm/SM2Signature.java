package com.github.wegoo.cain.asn1.gm;

import com.github.wegoo.cain.asn1.ASN1EncodableVector;
import com.github.wegoo.cain.asn1.ASN1Integer;
import com.github.wegoo.cain.asn1.ASN1Object;
import com.github.wegoo.cain.asn1.ASN1Primitive;
import com.github.wegoo.cain.asn1.ASN1Sequence;
import com.github.wegoo.cain.asn1.DERSequence;

/**
 * SM2Signature ::= SEQUENCE{
 *  r INTEGER,
 *  s INTEGER
 * }
 */
public class SM2Signature extends ASN1Object {
  private ASN1Integer r;
  private ASN1Integer s;


  public static SM2Signature getInstance(Object o){
    if (o instanceof SM2Signature) {
      return (SM2Signature)o;
    } else if (o != null) {
      return new SM2Signature(ASN1Sequence.getInstance(o));
    }
    return null;
  }

  private SM2Signature(ASN1Sequence seq) {
    r = ASN1Integer.getInstance(seq.getObjectAt(0));
    s = ASN1Integer.getInstance(seq.getObjectAt(1));
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector vector = new ASN1EncodableVector();
    vector.add(r);
    vector.add(s);
    return new DERSequence(vector);
  }
}
