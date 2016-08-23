package scorex.crypto.authds.sltree

import org.scalatest.prop.GeneratorDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}
import scorex.crypto.TestingCommons
import scorex.crypto.authds.binary.{SLTValue, SLTKey, SLTree}
import scorex.crypto.encode.Base58

import scala.util.{Try, Random}


class SLTreeSpecification extends PropSpec with GeneratorDrivenPropertyChecks with Matchers with TestingCommons {

  property("SLTree insert minimal case") {
    val slt = new SLTree()
    slt.insert(Base58.decode("kD1f").get, Base58.decode("Y7wC").get)
    slt.insert(Base58.decode("iy4A").get, Base58.decode("HMx").get)
    slt.insert(Base58.decode("VpBpsmh").get, Base58.decode("3CEV9pvxo").get)
    println(slt)

    val digest = slt.rootHash()
    val (success, proof) = slt.insert(Base58.decode("5Q").get, Base58.decode("pf7A").get)
    println(slt)
    success shouldBe true
    val (verifies, insertSuccess, newDigest) = proof.verifyInsert(digest).get
    verifies shouldBe true
    insertSuccess shouldBe true
    newDigest.get shouldEqual slt.rootHash()
  }

  property("SLTree proof double check") {
    val slt = new SLTree()
    forAll { (key: Array[Byte], value: Array[Byte], newVal: Array[Byte]) =>
      whenever(key.nonEmpty && value.nonEmpty && newVal.nonEmpty && slt.lookup(key)._1.isEmpty) {
        val digest = slt.rootHash()
        val (success, proof) = slt.insert(key, value)
        success shouldBe true
        proof.isValid(digest) shouldBe true
        proof.isValid(digest) shouldBe true

        val digest2 = slt.rootHash()
        val (valueOpt, lookupProof) = slt.lookup(key)
        valueOpt.get shouldBe value
        lookupProof.isValid(digest2) shouldBe true
        lookupProof.isValid(digest2) shouldBe true

        val (successUpdate, updateProof) = slt.update(key, newVal)
        successUpdate shouldBe true
        slt.lookup(key)._1.get shouldBe newVal
        updateProof.isValid(digest2) shouldBe true
        updateProof.isValid(digest2) shouldBe true
      }
    }
  }

  property("SLTree insert one") {
    forAll {
      (key: Array[Byte], value: Array[Byte]) =>
        whenever(key.nonEmpty && value.nonEmpty) {
          val slt = new SLTree()
          val digest = slt.rootHash()
          val (success, proof) = slt.insert(key, value)
          success shouldBe true
          val (verifies, insertSuccess, newDigest) = proof.verifyInsert(digest).get
          verifies shouldBe true
          insertSuccess shouldBe true
          newDigest.get shouldEqual slt.rootHash()
        }
    }
  }


  property("SLTree insert") {
    val slt = new SLTree()
    forAll { (key: Array[Byte], value: Array[Byte]) =>
      whenever(key.nonEmpty && value.nonEmpty && slt.lookup(key)._1.isEmpty) {
        val digest = slt.rootHash()
        val (success, proof) = slt.insert(key, value)
        success shouldBe true
        val (verifies, insertSuccess, newDigest) = proof.verifyInsert(digest).get
        verifies shouldBe true
        insertSuccess shouldBe true
        newDigest.get shouldEqual slt.rootHash()
      }
    }
  }

  property("SLTree lookup one") {
    forAll { (key: Array[Byte], value: Array[Byte]) =>
      whenever(key.nonEmpty && value.nonEmpty) {
        val slt = new SLTree()
        val digest = slt.rootHash()
        val (success, proof) = slt.insert(key, value)
        success shouldBe true
        proof.isValid(digest) shouldBe true

        val digest2 = slt.rootHash()
        val (valueOpt, lookupProof) = slt.lookup(key)
        valueOpt.get shouldBe value
        lookupProof.isValid(digest2) shouldBe true
      }
    }
  }

  property("SLTree lookup") {
    val slt = new SLTree()
    forAll { (key: Array[Byte], value: Array[Byte]) =>
      whenever(key.nonEmpty && value.nonEmpty && slt.lookup(key)._1.isEmpty) {
        val digest = slt.rootHash()
        val (success, proof) = slt.insert(key, value)
        success shouldBe true
        proof.isValid(digest) shouldBe true

        val digest2 = slt.rootHash()
        val (valueOpt, lookupProof) = slt.lookup(key)
        valueOpt.get shouldBe value
        lookupProof.isValid(digest2) shouldBe true
      }
    }
  }

  property("SLTree non-existent lookup") {
    val slt = new SLTree()
    forAll { (key: Array[Byte]) =>
      whenever(key.nonEmpty && slt.lookup(key)._1.isEmpty) {
        val digest = slt.rootHash()

        val (valueOpt, lookupProof) = slt.lookup(key)
        valueOpt shouldBe None
        lookupProof.isValid(digest) shouldBe true
      }
    }
  }

  property("SLTree update one ") {
    forAll { (key: Array[Byte], value: Array[Byte], newVal: Array[Byte]) =>
      whenever(key.nonEmpty && value.nonEmpty && newVal.nonEmpty) {
        val slt = new SLTree()
        slt.topNode.right.isDefined shouldBe false
        val digest = slt.rootHash()
        val (success, proof) = slt.insert(key, value)
        success shouldBe true
        proof.isValid(digest) shouldBe true

        val digest2 = slt.rootHash()
        val (successUpdate, updateProof) = slt.update(key, newVal)
        successUpdate shouldBe true
        slt.lookup(key)._1.get shouldBe newVal
        val (verifies, found, newDigest) = updateProof.verifyUpdate(digest2).get
        verifies shouldBe true
        found shouldBe true
        newDigest.get shouldEqual slt.rootHash()
      }
    }
  }

  property("SLTree update") {
    val slt = new SLTree()
    forAll { (key: Array[Byte], value: Array[Byte], newVal: Array[Byte]) =>
      whenever(key.nonEmpty && value.nonEmpty && newVal.nonEmpty && slt.lookup(key)._1.isEmpty) {
        val digest = slt.rootHash()
        val (success, proof) = slt.insert(key, value)
        success shouldBe true
        proof.isValid(digest) shouldBe true

        val digest2 = slt.rootHash()
        val (successUpdate, updateProof) = slt.update(key, newVal)
        successUpdate shouldBe true
        slt.lookup(key)._1.get shouldBe newVal
        val (verifies, found, newDigest) = updateProof.verifyUpdate(digest2).get
        verifies shouldBe true
        found shouldBe true
        newDigest.get shouldEqual slt.rootHash()
      }
    }
  }


}