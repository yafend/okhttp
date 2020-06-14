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

import okio.IOException

/**
 * Reads a DER tag class, tag, length, and value and decodes it as value.
 */
internal abstract class DerAdapter<T>(
  val tagClass: Int,
  val tag: Long,
  val isOptional: Boolean = false,
  val defaultValue: T? = null
) {
  fun readWithTagAndLength(reader: DerReader): T? {
    if (!reader.next()) {
      if (!isOptional) throw IOException("expected ${tagClass}/${tag} not found"
      )
      return defaultValue
    }

    if (reader.tag != tag || reader.tagClass != tagClass) {
      throw IOException("expected ${tagClass}/${tag} but was $tagClass/$tag")
    }

    val result = reader.push {
      read(reader)
    }

    if (reader.next()) throw IOException("unexpected ${reader.tagClass}/${reader.tag}"
    )

    return result
  }

  abstract fun read(reader: DerReader): T

  /** Returns a copy of this adapter with a different tag class, tag, or default. */
  fun copy(
    tagClass: Int = this.tagClass,
    tag: Long = this.tag,
    isOptional: Boolean = this.isOptional,
    defaultValue: T? = this.defaultValue
  ): DerAdapter<T> = object : DerAdapter<T>(tagClass, tag, isOptional, defaultValue) {
    override fun read(reader: DerReader) = this@DerAdapter.read(reader)
  }

  override fun toString() = "$tagClass/$tag"

  companion object {
    val INTEGER_AS_LONG = object : DerAdapter<Long>(
        tagClass = DerReader.TAG_CLASS_UNIVERSAL,
        tag = DerReader.TAG_INTEGER
    ) {
      override fun read(reader: DerReader) = reader.readLong()
    }
  }
}
