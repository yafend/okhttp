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

internal class DerSequenceAdapter<T>(
  tagClass: Int = DerReader.TAG_CLASS_UNIVERSAL,
  tag: Long = DerReader.TAG_SEQUENCE,
  isOptional: Boolean = false,
  defaultValue: T? = null,
  val members: List<DerAdapter<*>>,
  val constructor: (List<*>) -> T
) : DerAdapter<T>(tagClass, tag, isOptional, defaultValue) {
  override fun read(reader: DerReader): T {
    val list = mutableListOf<Any?>()
    var tag: Long = -1L
    var tagClass: Int = -1

    while (list.size < members.size) {
      val member = members[list.size]

      if (tag == -1L && tagClass == -1 && reader.next()) {
        tag = reader.tag
        tagClass = reader.tagClass
      }

      if (tag == member.tag && tagClass == member.tagClass) {
        reader.push {
          val value = member.read(reader)
          list += value
        }
        tag = -1L
        tagClass = -1
      } else if (member.isOptional) {
        list += member.defaultValue
      } else if (tagClass == -1 && tag == -1L) {
        throw IOException("expected ${member.tagClass}/${member.tag} not found")
      } else {
        throw IOException("expected ${member.tagClass}/${member.tag} but was $tagClass/$tag")
      }
    }

    if (reader.next()) throw IOException("unexpected ${reader.tagClass}/${reader.tag}")

    return constructor(list)
  }
}
