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
import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.encodeUtf8
import org.assertj.core.api.Assertions.assertThat
import org.junit.Test

class DerReaderTest {
  @Test fun `tag and length`() {
    val buffer = Buffer()
        .writeByte(0b00011110)
        .writeByte(0b10000001)
        .writeByte(0b11001001)

    val derReader = DerReader(buffer)
    assertThat(derReader.next()).isTrue()
    assertThat(derReader.tag).isEqualTo(30)
    assertThat(derReader.constructed).isFalse()
    assertThat(derReader.tag).isEqualTo(30)
    assertThat(derReader.length).isEqualTo(201)
    assertThat(derReader.next()).isFalse()
  }

  @Test fun `primitive bit string`() {
    val buffer = Buffer()
        .write("0307040A3B5F291CD0".decodeHex())

    val derReader = DerReader(buffer)
    assertThat(derReader.next()).isTrue()
    assertThat(derReader.tag).isEqualTo(3L)
    derReader.push {
      assertThat(derReader.readBitString()).isEqualTo("0A3B5F291CD0".decodeHex())
      assertThat(derReader.trailingBits).isEqualTo(4)
    }
    assertThat(derReader.next()).isFalse()
  }

  @Test fun `constructed bit string`() {
    val buffer = Buffer()
        .write("2380".decodeHex())
        .write("0303000A3B".decodeHex())
        .write("0305045F291CD0".decodeHex())
        .write("0000".decodeHex())

    val derReader = DerReader(buffer)
    assertThat(derReader.next()).isTrue()
    assertThat(derReader.tag).isEqualTo(3L)
    derReader.push {
      assertThat(derReader.readBitString()).isEqualTo("0A3B5F291CD0".decodeHex())
      assertThat(derReader.trailingBits).isEqualTo(4)
    }
    assertThat(derReader.next()).isFalse()
  }

  @Test fun sequence() {
    val buffer = Buffer()
        .write("300A".decodeHex())
        .write("1505".decodeHex())
        .write("Smith".encodeUtf8())
        .write("01".decodeHex())
        .write("01".decodeHex())
        .write("FF".decodeHex())

    val derReader = DerReader(buffer)
    assertThat(derReader.next()).isTrue()
    assertThat(derReader.tag).isEqualTo(16L)
    derReader.push {
      assertThat(derReader.next()).isTrue()
      assertThat(derReader.tag).isEqualTo(21L)
      derReader.push {
        assertThat(derReader.readOctetString()).isEqualTo("Smith".encodeUtf8())
      }
      assertThat(derReader.next()).isTrue()
      assertThat(derReader.tag).isEqualTo(1L)
      derReader.push {
        assertThat(derReader.readBoolean()).isTrue()
      }
      assertThat(derReader.next()).isFalse()
    }
  }

  @Test fun `primitive string`() {
    val buffer = Buffer()
        .write("1A054A6F6E6573".decodeHex())

    val derReader = DerReader(buffer)
    assertThat(derReader.next()).isTrue()
    assertThat(derReader.tag).isEqualTo(26L)
    assertThat(derReader.constructed).isFalse()
    assertThat(derReader.tagClass).isEqualTo(DerReader.TAG_CLASS_UNIVERSAL)
    derReader.push {
      assertThat(derReader.readOctetString()).isEqualTo("Jones".encodeUtf8())
    }
    assertThat(derReader.next()).isFalse()
  }

  @Test fun `constructed string`() {
    val buffer = Buffer()
        .write("3A0904034A6F6E04026573".decodeHex())

    val derReader = DerReader(buffer)
    assertThat(derReader.next()).isTrue()
    assertThat(derReader.tag).isEqualTo(26L)
    assertThat(derReader.constructed).isTrue()
    assertThat(derReader.tagClass).isEqualTo(DerReader.TAG_CLASS_UNIVERSAL)
    derReader.push {
      assertThat(derReader.readOctetString()).isEqualTo("Jones".encodeUtf8())
    }
    assertThat(derReader.next()).isFalse()
  }

  @Test fun `implicit prefixed type`() {
    // Type1 ::= VisibleString
    // Type2 ::= [APPLICATION 3] IMPLICIT Type1
    val buffer = Buffer()
        .write("43054A6F6E6573".decodeHex())

    val derReader = DerReader(buffer)
    assertThat(derReader.next()).isTrue()
    assertThat(derReader.tag).isEqualTo(3L)
    assertThat(derReader.tagClass).isEqualTo(DerReader.TAG_CLASS_APPLICATION)
    derReader.push {
      assertThat(derReader.readOctetString()).isEqualTo("Jones".encodeUtf8())
    }
    assertThat(derReader.next()).isFalse()
  }

  @Test fun `tagged implicit prefixed type`() {
    // Type1 ::= VisibleString
    // Type2 ::= [APPLICATION 3] IMPLICIT Type1
    // Type3 ::= [2] Type2
    val buffer = Buffer()
        .write("A20743054A6F6E6573".decodeHex())

    val derReader = DerReader(buffer)
    assertThat(derReader.next()).isTrue()
    assertThat(derReader.tag).isEqualTo(2L)
    assertThat(derReader.tagClass).isEqualTo(DerReader.TAG_CLASS_CONTEXT_SPECIFIC)
    assertThat(derReader.length).isEqualTo(7L)
    assertThat(derReader.next()).isTrue()
    assertThat(derReader.tag).isEqualTo(3L)
    assertThat(derReader.tagClass).isEqualTo(DerReader.TAG_CLASS_APPLICATION)
    assertThat(derReader.length).isEqualTo(5L)
    derReader.push {
      assertThat(derReader.readOctetString()).isEqualTo("Jones".encodeUtf8())
    }
    assertThat(derReader.next()).isFalse()
  }

  @Test fun `implicit tagged implicit prefixed type`() {
    // Type1 ::= VisibleString
    // Type2 ::= [APPLICATION 3] IMPLICIT Type1
    // Type3 ::= [2] Type2
    // Type4 ::= [APPLICATION 7] IMPLICIT Type3
    val buffer = Buffer()
        .write("670743054A6F6E6573".decodeHex())

    val derReader = DerReader(buffer)
    assertThat(derReader.next()).isTrue()
    assertThat(derReader.tag).isEqualTo(7L)
    assertThat(derReader.tagClass).isEqualTo(DerReader.TAG_CLASS_APPLICATION)
    assertThat(derReader.length).isEqualTo(7L)
    assertThat(derReader.next()).isTrue()
    assertThat(derReader.tag).isEqualTo(3L)
    assertThat(derReader.tagClass).isEqualTo(DerReader.TAG_CLASS_APPLICATION)
    assertThat(derReader.length).isEqualTo(5L)
    derReader.push {
      assertThat(derReader.readOctetString()).isEqualTo("Jones".encodeUtf8())
    }
    assertThat(derReader.next()).isFalse()
  }

  @Test fun `implicit implicit prefixed type`() {
    // Type1 ::= VisibleString
    // Type2 ::= [APPLICATION 3] IMPLICIT Type1
    // Type5 ::= [2] IMPLICIT Type2
    val buffer = Buffer()
        .write("82054A6F6E6573".decodeHex())

    val derReader = DerReader(buffer)
    assertThat(derReader.next()).isTrue()
    assertThat(derReader.tag).isEqualTo(2L)
    assertThat(derReader.tagClass).isEqualTo(DerReader.TAG_CLASS_CONTEXT_SPECIFIC)
    assertThat(derReader.length).isEqualTo(5L)
    derReader.push {
      assertThat(derReader.readOctetString()).isEqualTo("Jones".encodeUtf8())
    }
    assertThat(derReader.next()).isFalse()
  }

  @Test fun `object identifier`() {
    val buffer = Buffer()
        .write("0603883703".decodeHex())

    val derReader = DerReader(buffer)
    assertThat(derReader.next()).isTrue()
    assertThat(derReader.tag).isEqualTo(6L)
    assertThat(derReader.tagClass).isEqualTo(DerReader.TAG_CLASS_UNIVERSAL)
    assertThat(derReader.length).isEqualTo(3L)
    derReader.push {
      assertThat(derReader.readObjectIdentifier()).isEqualTo(listOf(2L, 999L, 3L))
    }
    assertThat(derReader.next()).isFalse()
  }

  @Test fun `relative object identifier`() {
    val buffer = Buffer()
        .write("0D04c27B0302".decodeHex())

    val derReader = DerReader(buffer)
    assertThat(derReader.next()).isTrue()
    assertThat(derReader.tag).isEqualTo(13L)
    assertThat(derReader.tagClass).isEqualTo(DerReader.TAG_CLASS_UNIVERSAL)
    assertThat(derReader.length).isEqualTo(4L)
    derReader.push {
      assertThat(derReader.readRelativeObjectIdentifier()).isEqualTo(listOf(8571L, 3L, 2L))
    }
    assertThat(derReader.next()).isFalse()
  }

  @Test
  fun happyPath() {
    val certificateString = """
      -----BEGIN CERTIFICATE-----
      MIIBmjCCAQOgAwIBAgIBATANBgkqhkiG9w0BAQsFADATMREwDwYDVQQDEwhjYXNo
      LmFwcDAeFw03MDAxMDEwMDAwMDBaFw03MDAxMDEwMDAwMDFaMBMxETAPBgNVBAMT
      CGNhc2guYXBwMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCApFHhtrLan28q
      +oMolZuaTfWBA0V5aMIvq32BsloQu6LlvX1wJ4YEoUCjDlPOtpht7XLbUmBnbIzN
      89XK4UJVM6Sqp3K88Km8z7gMrdrfTom/274wL25fICR+yDEQ5fUVYBmJAKXZF1ao
      I0mIoEx0xFsQhIJ637v2MxJDupd61wIDAQABMA0GCSqGSIb3DQEBCwUAA4GBADam
      UVwKh5Ry7es3OxtY3IgQunPUoLc0Gw71gl9Z+7t2FJ5VkcI5gWfutmdxZ2bDXCI8
      8V0vxo1pHXnbBrnxhS/Z3TBerw8RyQqcaWOdp+pBXyIWmR+jHk9cHZCqQveTIBsY
      jaA9VEhgdaVhxBsT2qzUNDsXlOzGsliznDfoqETb
      -----END CERTIFICATE-----
      """.trimIndent()
  }
}
