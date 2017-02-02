package scorex.crypto.hash

import org.scalatest.{Matchers, PropSpec}
import scorex.utils.BytesHex.hex2bytes

/**
 * Test vectors from
 * [[https://www.cosic.esat.kuleuven.be/nessie/testvectors/hash/sha/Sha-2-256.unverified.test-vectors Project NESSIE - New European Schemes for Signature, Integrity, and Encryption]]
 */
class SHA256NessieSpecification extends PropSpec
with Matchers {

  property("Set 1, vector# 0") {
    Sha256("") shouldBe hex2bytes("" +
      "E3B0C44298FC1C149AFBF4C8996FB924" +
      "27AE41E4649B934CA495991B7852B855")
  }

  property("Set 1, vector# 1") {
    Sha256("a") shouldBe hex2bytes("" +
      "CA978112CA1BBDCAFAC231B39A23DC4D" +
      "A786EFF8147C4E72B9807785AFEE48BB")
  }

  property("Set 1, vector# 2") {
    Sha256("abc") shouldBe hex2bytes("" +
      "BA7816BF8F01CFEA414140DE5DAE2223" +
      "B00361A396177A9CB410FF61F20015AD")
  }

  property("Set 1, vector# 3") {
    Sha256("message digest") shouldBe hex2bytes("" +
      "F7846F55CF23E14EEBEAB5B4E1550CAD" +
      "5B509E3348FBC4EFA3A1413D393CB650")
  }

  property("Set 1, vector# 4") {
    Sha256("abcdefghijklmnopqrstuvwxyz") shouldBe hex2bytes("" +
      "71C480DF93D6AE2F1EFAD1447C66C952" +
      "5E316218CF51FC8D9ED832F2DAF18B73")
  }

  property("Set 1, vector# 5") {
    Sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") shouldBe hex2bytes("" +
      "248D6A61D20638B8E5C026930C3E6039" +
      "A33CE45964FF2167F6ECEDD419DB06C1")
  }

  property("Set 1, vector# 6") {
    Sha256("" +
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
      "abcdefghijklmnopqrstuvwxyz" +
      "0123456789") shouldBe hex2bytes("" +
      "DB4BFCBD4DA0CD85A60C3C37D3FBD880" +
      "5C77F15FC6B1FDFE614EE0A7C8FDB4C0")
  }

  property("Set 1, vector# 7") {
    Sha256("" +
      "1234567890" +
      "1234567890" +
      "1234567890" +
      "1234567890" +
      "1234567890" +
      "1234567890" +
      "1234567890" +
      "1234567890") shouldBe hex2bytes("" +
      "F371BC4A311F2B009EEF952DD83CA80E" +
      "2B60026C8E935592D0F9C308453C813E")
  }

  property("Set 2, vector# 8") {
    Sha256("\u0000") shouldBe hex2bytes("" +
      "6E340B9CFFB37A989CA544E6BB780A2C" +
      "78901D3FB33738768511A30617AFA01D")
  }

  property("Set 2, vector# 16") {
    Sha256("\u0000\u0000") shouldBe hex2bytes("" +
      "96A296D224F285C67BEE93C30F8A3091" +
      "57F0DAA35DC5B87E410B78630A09CFC7")
  }

  property("Set 2, vector# 24") {
    Sha256("\u0000\u0000\u0000") shouldBe hex2bytes("" +
      "709E80C88487A2411E1EE4DFB9F22A86" +
      "1492D20C4765150C0C794ABD70F8147C")
  }

  property("Set 2, vector# 32") {
    Sha256("\u0000\u0000\u0000\u0000") shouldBe hex2bytes("" +
      "DF3F619804A92FDB4057192DC43DD748" +
      "EA778ADC52BC498CE80524C014B81119")
  }

  property("Set 2, vector# 40") {
    Sha256("\u0000\u0000\u0000\u0000\u0000") shouldBe hex2bytes("" +
      "8855508AADE16EC573D21E6A485DFD0A" +
      "7624085C1A14B5ECDD6485DE0C6839A4")
  }

  property("Set 2, vector# 48") {
    Sha256("\u0000\u0000\u0000\u0000\u0000\u0000") shouldBe hex2bytes("" +
      "B0F66ADC83641586656866813FD9DD0B" +
      "8EBB63796075661BA45D1AA8089E1D44")
  }

  property("Set 2, vector# 56") {
    Sha256("\u0000\u0000\u0000\u0000\u0000\u0000\u0000") shouldBe hex2bytes("" +
      "837885C8F8091AEAEB9EC3C3F85A6FF4" +
      "70A415E610B8BA3E49F9B33C9CF9D619")
  }

  property("Set 2, vector# 64") {
    Sha256("\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000") shouldBe hex2bytes("" +
      "AF5570F5A1810B7AF78CAF4BC70A660F" +
      "0DF51E42BAF91D4DE5B2328DE0E83DFC")
  }

  property("Set 2, vector# 72") {
    Sha256("\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000") shouldBe hex2bytes("" +
      "3E7077FD2F66D689E0CEE6A7CF5B37BF" +
      "2DCA7C979AF356D0A31CBC5C85605C7D")
  }

  property("Set 2, vector# 80") {
    Sha256("\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000") shouldBe hex2bytes("" +
      "01D448AFD928065458CF670B60F5A594" +
      "D735AF0172C8D67F22A81680132681CA")
  }

  property("Set 2, vector# 88") {
    Sha256("\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000") shouldBe hex2bytes("" +
      "71B6C1D53832F789A7F2435A7C629245" +
      "FA3761AD8487775EBF4957330213A706")
  }

  property("Set 2, vector# 96") {
    Sha256("\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000") shouldBe hex2bytes("" +
      "15EC7BF0B50732B49F8228E07D243653" +
      "38F9E3AB994B00AF08E5A3BFFE55FD8B")
  }

  property("Set 2, vector# 104") {
    Sha256("\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000") shouldBe hex2bytes("" +
      "DD46C3EEBB1884FF3B5258C0A2FC9398" +
      "E560A29E0780D4B53869B6254AA46A96")
  }

  property("Set 2, vector# 112") {
    Sha256("\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000") shouldBe hex2bytes("" +
      "E7ECEBBC590BC88B3761FA6CD03D749F" +
      "87463DABB67021A5C6768C25EC68B3F2")
  }

  property("Set 2, vector# 120") {
    Sha256("\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000") shouldBe hex2bytes("" +
      "5322FECFC92A5E3248A297A3DF3EDDFB" +
      "9BD9049504272E4F572B87FA36D4B3BD")
  }
}
