(ns org.clojars.making.clj-aws-ecs
  (:import (java.net URLDecoder URLEncoder)
           (java.text DateFormat SimpleDateFormat)
           (java.util Calendar Map SortedMap TimeZone TreeMap)
           (javax.crypto Mac)
           (javax.crypto.spec SecretKeySpec)
           (org.apache.commons.codec.binary Base64)
           (javax.xml.parsers DocumentBuilder DocumentBuilderFactory)
           )
  (:require [clojure.xml :as xml])
  (:use [clojure.contrib.str-utils :only (str-join)]
        org.clojars.making.clj-aws-ecs.requester
        )
  )

(defn make-requester [endpoint  access-key-id secret-key]
  ""
  (let [secret-key-bytes (.getBytes secret-key UTF8_CHARSET)
        secret-key-spec (SecretKeySpec. secret-key-bytes HMAC_SHA256_ALGORITHM)
        mac (Mac/getInstance HMAC_SHA256_ALGORITHM)]
    (.init mac secret-key-spec)
    (struct-map signed-requester :endpoint endpoint :access-key-id access-key-id :secret-key secret-key
                :secret-key-spec secret-key-spec :mac mac)))

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

(defmacro defitemrequest [fname & body]
  (let [uri-fname (symbol (str fname "-uri"))]
  `(do
     (defn ~uri-fname ~@body)
     (defn ~(symbol (str fname "-map")) [& args#]
       (xml/parse (apply ~uri-fname args#)))
     (defn ~(symbol (str fname "-doc")) [& args#]
       (let [builder# (.newDocumentBuilder (DocumentBuilderFactory/newInstance))]
         (.parse builder# (apply ~uri-fname args#)))))
  ))

(defn item-request-uri [requester params]
  (let [default-params {"Service" "AWSECommerceService",
                        "Version" "2009-03-31",
                        "ResponseGroup" "Small"}
        params (conj default-params params)
        builder (.newDocumentBuilder (DocumentBuilderFactory/newInstance))
        ]
    (sign requester params)))

(defitemrequest item-lookup
  "(item-lookup-uri requester \"1430272317\") -> request uri
   (item-lookup-map requester \"1430272317\") -> result of clojure.xml/parse
   (item-lookup-doc requester \"1430272317\") -> result of javax.xml.parsers.DocumentBuilder/parse

   example : (.getTextContent (.item (.getElementsByTagName (item-lookup-doc requester \"1430272317\") \"Title\") 0))
            -> \"Practical Clojure (The Definitive Guide)\"
  "
  ([requester item-id other-param]
     (item-request-uri requester (conj other-param {"Operation" "ItemLookup", "ItemId" item-id})))
  ([requester item-id]
     (item-lookup-uri requester item-id {})))

(defitemrequest item-search  
  "(item-search-uri requester \"Books\" \"Clojure\") -> request uri
   (item-search-map requester \"Books\" \"Clojure\") -> result of clojure.xml/parse
   (item-search-doc requester \"Books\" \"Clojure\") -> result of javax.xml.parsers.DocumentBuilder/parse
  "
  ([requester search-index keywords other-param]
     (item-request-uri requester (conj other-param {"Operation" "ItemSearch", "SearchIndex" search-index, "Keywords" keywords})))
  ([requester search-index keywords]
     (item-search-uri requester search-index keywords {})))

