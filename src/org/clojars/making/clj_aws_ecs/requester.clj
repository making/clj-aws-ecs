(ns org.clojars.making.clj-aws-ecs.requester
  (:import (java.net URLDecoder URLEncoder)
           (java.text DateFormat SimpleDateFormat)
           (java.util Calendar Map SortedMap TimeZone TreeMap)
           (javax.crypto Mac)
           (javax.crypto.spec SecretKeySpec)
           (org.apache.commons.codec.binary Base64)
           )
  (:use [clojure.contrib.str-utils :only (str-join)])
  )

(def UTF8_CHARSET "UTF-8")
(def HMAC_SHA256_ALGORITHM "HmacSHA256")
(def REQUEST_URI "/onca/xml")
(def REQUEST_METHOD "GET")

(defstruct signed-requester :endpoint :access-key-id :secret-key)

(defn hmac [#^Mac mac #^String str]
  (String. (.encode (Base64. 0) (.doFinal mac (.getBytes str UTF8_CHARSET)))))

(defn percent-encode-rfc3986 [s]
  "Percent-encode values according the RFC 3986. The built-in Java
   URLEncoder does not encode according to the RFC, so we make the extra replacements."
  (-> (URLEncoder/encode s UTF8_CHARSET) 
      (.replace "+" "%20") 
      (.replace "*" "%2A") 
      (.replace "%7E" "~")))

(defn canonicalize [#^Map params]
  "Canonicalize the query string as required by Amazon."
  (if (empty? params) "" 
      (str-join \& (for [e params] 
                     (str (percent-encode-rfc3986 (.getKey e)) \= (percent-encode-rfc3986 (.getValue e)))))))

(defn timestamp []
  "Generate a ISO-8601 format timestamp as required by Amazon."
  (.format (doto (SimpleDateFormat. "yyyy-MM-dd'T'HH:mm:ss'Z'")
             (.setTimeZone (TimeZone/getTimeZone "GMT")))
           (.getTime (Calendar/getInstance))))

(defn create-parameter-map #^Map [#^String query]
  "Takes a query string, separates the constituent name-value pairs and stores them in a hashmap."
  (let [pairs (.split query "&")]
    (apply hash-map 
           (reduce into
                   (for [pair pairs :when (not-empty pair)]
                     (let [tokens (map #(URLDecoder/decode % UTF8_CHARSET) (.split pair "=" 2))]
                       (condp = (count tokens)
                         1 (if (= (first pair) \=) ["" (first tokens)] [(first tokens) ""])
                         2 (vec tokens))))))))
