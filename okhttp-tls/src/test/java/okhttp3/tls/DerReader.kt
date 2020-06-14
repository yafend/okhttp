/*
 * Copyright (C) 2020 Square, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package okhttp3.tls

import okio.Buffer
import okio.BufferedSource
import okio.ByteString
import okio.ForwardingSource
import okio.Source
import okio.buffer
import java.math.BigInteger
import java.net.ProtocolException

/**
 * ASN.1: encoding
 * DER: distinguished rules to constrain ASN.1
 * BER: basic rules to constrain ASN.1
 *
 * Distinguished Encoding Rules (DER) as specified by X.690.
 *
 * https://www.itu.int/rec/T-REC-X.690
 *
 * Abstract Syntax Notation One (ASN.1)
 */
internal class DerReader(source: Source) {
  // BigInteger (1008 bytes)
  // PrintableString, UTF8String, and IA5String

  // PrintableString
  // A restricted subset of ASCII, allowing:
  // alphanumerics,
  // spaces, and
  // a specific handful of punctuation: ' () + , - . / : = ?.
  // Notably it doesn’t include * or @.
  // There are no storage-size benefits to more restrictive string types.

  // IA5String, based on International Alphabet No. 5, is more permissive:
  // It allows nearly any ASCII character,
  // and is used for email address,
  // DNS names,
  // and URLs in certificates.
  // Note that there are a few byte values where the IA5 meaning of the byte value is different than
  // the US-ASCII meaning of that same value.

  // TeletexString, BMPString, and UniversalString are deprecated for use in HTTPS certificates, but
  // you may see them when parsing older CA certificates, which are long-lived and may predate the
  // deprecation.

  // UTCTime
  // represents a date and time as YYMMDDhhmm[ss], with an optional timezone offset or “Z” to
  // represent Zulu (aka UTC aka 0 timezone offset). For instance the UTCTimes 820102120000Z and
  // 820102070000-0500 both represent the same time: January 2nd, 1982, at 7am in New York City
  // (UTC-5) and at 12pm in UTC.
  // it represents dates from 1950 to 2050. RFC 5280 also requires that the “Z” timezone must be
  // used and seconds must be included.

  // GeneralizedTime
  // GeneralizedTime supports dates after 2050 through the simple expedient of representing the year
  // with four digits. It also allows fractional seconds (weirdly, with either a comma or a full
  // stop as the decimal separator). RFC 5280 forbids fractional seconds and requires the “Z.”

  // Don’t let the names fool you: These are two very different types. A SEQUENCE is equivalent to
  // “struct” in most programming languages. It holds a fixed number of fields of different types.
  // For instance, see the Certificate example below.

  // A SEQUENCE OF, on the other hand, holds an arbitrary number of fields of a single type. This is
  // analogous to an array or a list in a programming language. For instance:

  private val countingSource: CountingSource = CountingSource(source)
  private val source: BufferedSource = countingSource.buffer()

  /** Total bytes read thus far. */
  private val byteCount: Long
    get() = countingSource.bytesRead - source.buffer.size

  /** How many bytes to read before [next] should return false, or -1L for no limit. */
  var limit: Long = -1L

  private val bytesLeft: Long
    get() = if (limit == -1L) -1L else limit - byteCount

  /** Bits 7,8. 00=Universal, 01=Application, 10=Context-Specific, 11=Private */
  var tagClass: Int = -1
    private set

  var tag: Long = -1L
    private set

  /** Bit 6. 0=Primitive, 1=Constructed */
  var constructed: Boolean = false
    private set

  var length: Long = -1L
    private set

  /** Number of trailing bits in the last call to [readBitString]. */
  var trailingBits = -1
    private set

  inline fun <T> push(block: () -> T): T {
    val pushedLimit = limit
    val pushedTagClass = tagClass
    val pushedTag = tag
    val pushedLength = length
    val pushedConstructed = constructed

    limit = if (length != -1L) byteCount + length else -1L
    tagClass = -1
    tag = -1L
    length = -1L
    try {
      return block()
    } finally {
      limit = pushedLimit
      tagClass = pushedTagClass
      tag = pushedTag
      length = pushedLength
      constructed = pushedConstructed
    }
  }

  /**
   * Returns true if a tag was read and there's a value to process.
   *
   * This returns false if:
   *
   *  * The stream is exhausted.
   *  * We've read all of the bytes of an object whose length is known.
   *  * We've reached the [TAG_END_OF_CONTENTS] of an object whose length is unknown.
   */
  fun next(): Boolean {
    if (byteCount == limit) {
      return false // We've hit a local limit.
    }

    if (limit == -1L && source.exhausted()) {
      return false // We've exhausted the source stream.
    }

    // Read the tag.
    val tagAndClass = source.readByte().toInt() and 0xff
    tagClass = tagAndClass and 0b1100_0000
    constructed = (tagAndClass and 0b0010_0000) == 0b0010_0000
    val tag0 = tagAndClass and 0b0001_1111 // TODO: confirm 31 is right here, breaks SET OF
    if (tag0 == 0b0001_1111) {
      var tagBits = 0L
      while (true) {
        val tagN = source.readByte().toInt() and 0xff
        tagBits += (tagN and 0b0111_1111)
        if (tagN and 0b1000_0000 == 0b1000_0000) break
        tagBits = tagBits shl 7
      }
      tag = tagBits
    } else {
      tag = tag0.toLong()
    }

    // Read the length.
    val length0 = source.readByte().toInt() and 0xff
    if (length0 == 0b1000_0000) {
      // Indefinite length.
      length = -1L
    } else if (length0 and 0b1000_0000 == 0b1000_0000) {
      // Length specified over multiple bytes.
      val lengthBytes = length0 and 0b0111_1111
      var lengthBits = source.readByte()
          .toLong() and 0xff
      for (i in 1 until lengthBytes) {
        lengthBits = lengthBits shl 8
        lengthBits += source.readByte()
            .toInt() and 0xff
      }
      length = lengthBits
    } else {
      // Length is 127 or fewer bytes.
      length = (length0 and 0b0111_1111).toLong()
    }

    return tagClass != TAG_CLASS_UNIVERSAL || tag != TAG_END_OF_CONTENTS
  }

  fun readBoolean(): Boolean {
    // TODO(jwilson): is the tag always 1 ?
    if (bytesLeft != 1L) throw ProtocolException("unexpected length: $bytesLeft")
    return source.readByte().toInt() != 0
  }

  fun readBigInteger(): BigInteger {
    if (bytesLeft == 0L) throw ProtocolException("unexpected length: $bytesLeft")

    val byteArray = source.readByteArray(bytesLeft)
    return BigInteger(byteArray)
  }

  fun readLong(): Long {
    if (bytesLeft !in 1..8) throw ProtocolException("unexpected length: $bytesLeft")

    var result = source.readByte().toLong() // No "and 0xff" because this is a signed value.
    while (byteCount < limit) {
      result = result shl 8
      result += source.readByte().toInt() and 0xff
    }
    return result
  }

  fun readBitString(): ByteString {
    val buffer = Buffer()
    readBitString(buffer)
    return buffer.readByteString()
  }

  fun readBitString(sink: Buffer) {
    if (bytesLeft != -1L) {
      trailingBits = source.readByte().toInt() and 0xff
      source.read(sink, bytesLeft)
    } else {
      while (next()) {
        push {
          readBitString(sink)
        }
      }
    }
  }

  fun readOctetString(): ByteString {
    val buffer = Buffer()
    readOctetString(buffer)
    return buffer.readByteString()
  }

  fun readOctetString(sink: Buffer) {
    if (bytesLeft != -1L && !constructed) {
      source.read(sink, bytesLeft)
    } else {
      while (next()) {
        push {
          readOctetString(sink)
        }
      }
    }
  }

  fun readObjectIdentifier(): List<Long> {
    val result = mutableListOf<Long>()
    when (val xy = readSubidentifier()) {
      in 0L until 40L -> {
        result += 0L
        result += xy
      }
      in 40L until 80L -> {
        result += 1L
        result += xy - 40L
      }
      else -> {
        result += 2L
        result += xy - 80L
      }
    }
    while (byteCount < limit) {
      result += readSubidentifier()
    }
    return result
  }

  fun readRelativeObjectIdentifier(): List<Long> {
    val result = mutableListOf<Long>()
    while (byteCount < limit) {
      result += readSubidentifier()
    }
    return result
  }

  private fun readSubidentifier(): Long {
    var result = 0L
    while (true) {
      val byteN = source.readByte().toLong() and 0xff
      if (byteN and 0b1000_0000L == 0b1000_0000L) {
        result = (result + (byteN and 0b0111_1111)) shl 7
      } else {
        return result + byteN
      }
    }
  }

  /** A source that keeps track of how many bytes it's consumed. */
  private class CountingSource(source: Source) : ForwardingSource(source) {
    var bytesRead = 0L

    override fun read(sink: Buffer, byteCount: Long): Long {
      val result = delegate.read(sink, byteCount)
      if (result == -1L) return -1L
      bytesRead += result
      return result
    }
  }

  companion object {
    /** Bits 7,8. 00=Universal, 01=Application, 10=Context-Specific, 11=Private */
    val TAG_CLASS_UNIVERSAL = 0b0000_0000
    val TAG_CLASS_APPLICATION = 0b0100_0000
    val TAG_CLASS_CONTEXT_SPECIFIC = 0b1000_0000
    val TAG_CLASS_PRIVATE = 0b1100_0000

    val TAG_END_OF_CONTENTS = 0L
    val TAG_INTEGER = 2L
    val TAG_BIT_STRING = 3L
    val TAG_OCTET_STRING = 4L
    val TAG_NULL = 5L
    val TAG_OBJECT_IDENTIFIER = 6L
    val TAG_UTF8_STRING = 12L
    val TAG_SEQUENCE = 16L
    val TAG_SEQUENCE_OF = 30L
    val TAG_SET = 17L
    val TAG_SET_OF = 31L
    val TAG_PRINTABLE_STRING = 19L
    val TAG_IA5_STRING = 22L
    val TAG_UTC_TIME = 23L
    val TAG_GENERALIZED_TIME = 24L
  }
}
