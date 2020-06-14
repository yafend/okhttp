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
import org.assertj.core.api.Assertions.assertThat
import org.junit.Test

internal class DerSequenceAdapterTest {
  @Test fun `decode point with only x set`() {
    val buffer = Buffer()
        .write("3003800109".decodeHex())
    val derReader = DerReader(buffer)
    val point = Point.ADAPTER.readWithTagAndLength(derReader)
    assertThat(point).isEqualTo(Point(9L, null))
  }

  @Test fun `decode point with only y set`() {
    val buffer = Buffer()
        .write("3003810109".decodeHex())
    val derReader = DerReader(buffer)
    val point = Point.ADAPTER.readWithTagAndLength(derReader)
    assertThat(point).isEqualTo(Point(null, 9L))
  }

  @Test fun `decode point with both fields set`() {
    val buffer = Buffer()
        .write("3006800109810109".decodeHex())
    val derReader = DerReader(buffer)
    val point = Point.ADAPTER.readWithTagAndLength(derReader)
    assertThat(point).isEqualTo(Point(9L, 9L))
  }

  /**
   * ```
   * Point ::= SEQUENCE {
   *   x [0] INTEGER OPTIONAL,
   *   y [1] INTEGER OPTIONAL
   * }
   * ```
   */
  data class Point(
    val x: Long?,
    val y: Long?
  ) {
    companion object {
      val ADAPTER = DerSequenceAdapter(
          members = listOf(
              DerAdapter.INTEGER_AS_LONG.copy(
                  tagClass = DerReader.TAG_CLASS_CONTEXT_SPECIFIC,
                  tag = 0,
                  isOptional = true
              ),
              DerAdapter.INTEGER_AS_LONG.copy(
                  tagClass = DerReader.TAG_CLASS_CONTEXT_SPECIFIC,
                  tag = 1,
                  isOptional = true
              )
          )
      ) {
        Point(it[0] as Long?, it[1] as Long?)
      }
    }
  }
}
