/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package au.net.zeus.hps;

/**
 * Exception indicating failed initialization of a security policy provider.
 *
 * @author Sun Microsystems, Inc.
 * 
 * @since 2.0
 */
public class PolicyInitializationException extends Exception {

    private static final long serialVersionUID = -7466794219271489139L;

    /**
     * Constructs new <code>PolicyInitializationException</code> with the
     * specified detail message and cause.
     *
     * @param   message detail message
     * @param   cause cause, or <code>null</code> if none or unknown
     */
    public PolicyInitializationException(String message, Throwable cause) {
	super(message, cause);
    }
}
