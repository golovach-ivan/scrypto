package scorex.crypto.ads.merkle

import scorex.crypto.ads.{LazyIndexedBlobStorage, StorageType}
import scorex.crypto.hash.CryptographicHash

trait MerkleTree[HashFn <: CryptographicHash, ST <: StorageType] {
  type Digest = HashFn#Digest

  def proofByIndex(index: Position): Option[MerklePath[HashFn]]
}


trait MerklizedSeq[HashFn <: CryptographicHash, ST <: StorageType] {
  protected val tree: MerkleTree[HashFn, ST]
  protected val seq: LazyIndexedBlobStorage[ST]

  def getDataElement(index: Long): Option[Array[Byte]] = seq.get(index)

  def byIndex(index: Position): Option[AuthDataBlock[HashFn]] = tree.proofByIndex(index) map { proof =>
    AuthDataBlock(getDataElement(index).get, proof)
  }
}


sealed trait MerklizedSeqModification {
  val position: Position
}


case class MerklizedSeqAppend(override val position: Position, element: Array[Byte]) extends MerklizedSeqModification

case class MerklizedSeqRemoval(override val position: Position) extends MerklizedSeqModification


trait VersionedMerklizedSeq[HashFn <: CryptographicHash, ST <: StorageType] extends MerklizedSeq[HashFn, ST] {
  val version: Long

  protected def setDataElement(index: Long, element: Array[Byte])

  def update(updatePlan: Iterable[MerklizedSeqModification]): VersionedMerklizedSeq[HashFn, ST] = {
    this
  }
}