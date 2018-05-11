(ns openid-client.handler
  (:require [ring.util.response :as resp]))

(defn create-handler
  [config & handlers]
  (let [handler-map (reduce
                     (fn [handler-map [method uri handler]]
                       (assoc-in handler-map [uri method] handler))
                     {}
                     handlers)]
    (fn [{:keys [uri request-method] :as request}]
      (if (get-in handler-map [uri request-method])
        (try
          ((get-in handler-map [uri request-method]) request)
          (catch Exception _ (resp/redirect (:error-uri config))))
        (-> (resp/not-found "NOT FOUND")
            (resp/content-type "text/plain"))))))
