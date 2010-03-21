(ns am.ik.clj-aws-ecs.requester
  (:import (java.net URLDecoder URLEncoder)
           (java.text DateFormat SimpleDateFormat)
           (java.util Calendar Map SortedMap TimeZone TreeMap)
           (javax.crypto Mac)
           (org.apache.commons.codec.binary Base64))
  (:use [clojure.contrib.str-utils :only (str-join)]))

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


(defmulti sign (fn [x y] (class y)))

(defmethod sign Map
  [requester #^Map params] 
  "This method signs requests in hashmap form. It returns a URL that should
   be used to fetch the response. The URL returned should not be modified in
   any way, doing so will invalidate the signature and Amazon will reject
   the request."
  (let [sorted-param (TreeMap. (conj {"AWSAccessKeyId" (:access-key-id requester),
                                      "Timestamp" (timestamp)
                                      } params))
        canonical-query (canonicalize sorted-param)
        to-sign (str-join "\n" (list REQUEST_METHOD (:endpoint requester) REQUEST_URI canonical-query))
        hmac (hmac (:mac requester) to-sign)
        sig (percent-encode-rfc3986 hmac)
        ]
    (str "http://" (:endpoint requester) REQUEST_URI "?" canonical-query "&Signature=" sig)))

(defmethod sign String
  [requester #^String query] 
  (sign requester (create-parameter-map query)))
