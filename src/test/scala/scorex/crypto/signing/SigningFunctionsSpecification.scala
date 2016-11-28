package scorex.crypto.signing

import org.scalatest.prop.{GeneratorDrivenPropertyChecks, PropertyChecks}
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.encode.Base58
import scorex.crypto.signatures.Curve25519


class SigningFunctionsSpecification extends PropSpec
  with PropertyChecks
  with GeneratorDrivenPropertyChecks
  with Matchers {


  property("Changed data for all signatures") {
    val signature = Base58.decode("5jpwaJnERa8Gr1ChgrNYnmxm2EtZ4KHC5bW1ZLL7LCY1bUV9gFWFAGjpJaPDCawmFzguqGBgYDyeocpEsKWeYDM1").get
    val pubkey = Base58.decode("Gx9dDNxzpALCowVuZb7pBceBLJugLA8sPa6TJDXrpfeW").get

    val d1 = Base58.decode("1112shApxzYHCAZHoGnedt4T3mtU6PPQY8zHhXj8wU91kHLB24nh6Hue3HhytjoQr3FNNV35pJjicUP7MLobeySbA5dgPLTXLEpsCH1GFedaSdV6oMi7").get
    val d2 = Base58.decode("1112shApxzhz8Zexvuf1VoHcektMfsi9fySzi16rvgwZUuSQjDzE3nFkXHgpurqD4brwX6TetExJBw9qAfZTe5nwMfmx6UUNxJkjpRdsFcyqct63V5Pu").get
    val v1 = Curve25519.verify(signature, d1, pubkey)
    val v2 = Curve25519.verify(signature, d2, pubkey)

    v1 || v2 shouldBe true
    v1 && v2 shouldBe false
  }

  property("signed message should be verifiable with appropriate public key") {
    forAll { (seed1: Array[Byte], seed2: Array[Byte],
              message1: Array[Byte], message2: Array[Byte]) =>
      whenever(!seed1.sameElements(seed2) && !message1.sameElements(message2)) {
        val keyPair = Curve25519.createKeyPair(seed1)
        val keyPair2 = Curve25519.createKeyPair(seed2)

        val sig = Curve25519.sign(keyPair._1, message1)
        val sigSized = Curve25519.signSized(keyPair._1, message1)

        Curve25519.verify(sig, message1, keyPair._2) shouldBe true
        Curve25519.verify(sig, message1, keyPair2._2) should not be true
        Curve25519.verify(sig, message2, keyPair._2) should not be true

        Curve25519.verify(sigSized, message1, keyPair._2) shouldBe true
        Curve25519.verify(sigSized, message1, keyPair2._2) should not be true
        Curve25519.verify(sigSized, message2, keyPair._2) should not be true

      }
    }
  }

  property("shared secret should be same for both parties ") {

    forAll { (seed1: Array[Byte], seed2: Array[Byte]) =>
      whenever(!seed1.sameElements(seed2)) {
        val keyPair1 = Curve25519.createKeyPair(seed1)
        val keyPair2 = Curve25519.createKeyPair(seed2)

        val shared = Curve25519.createSharedSecret(keyPair1._1, keyPair2._2)
        val sharedWithKeysReversed = Curve25519.createSharedSecret(keyPair2._1, keyPair1._2)

        val badSharedSecret1 = Curve25519.createSharedSecret(keyPair2._2, keyPair1._2)
        val badSharedSecret2 = Curve25519.createSharedSecret(keyPair2._2, keyPair1._2)

        shared.sameElements(sharedWithKeysReversed) should be(true)

        badSharedSecret1.sameElements(shared) shouldNot be(true)

        badSharedSecret2.sameElements(shared) shouldNot be(true)
      }
    }
  }

}