;;; gnus-gmail-oauth.el --- Perform GMail OAuth2 authentication for Gnus

;; Copyright © 2016 Gregorio Gervasio Jr. <gregorio.gervasio@gmail.com>

;; Author: Gregorio Gervasio Jr. <gregorio.gervasio@gmail.com>

;; Mostly copied from Julien Danjou's <julien@danjou.info> google-contacts
;; URL: http://julien.danjou.info/projects/emacs-packages#google-contacts

;; This file is NOT part of GNU Emacs.

;; GNU Emacs is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; GNU Emacs is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with GNU Emacs.  If not, see <http://www.gnu.org/licenses/>.

;;; Prerequisites:
;; oauth2
;; - available on ELPA
;; google-contacts
;; - https://github.com/jd/google-contacts.el

;;; Commentary:
;;
;; 1. obtain Google API credentials from:
;; http://console.developers.google.com/
;;
;; 2. set credentials:
;;
;; (setq gnus-gmail-oauth-client-id "xxxx.apps.googleusercontent.com")
;; (setq gnus-gmail-oauth-client-secret "xxxx")
;;
;; 3. set custom authenticator:
;;
;; (require 'gnus-gmail-oauth)
;; (advice-add 'nnimap-login :before-until #'gnus-gmail-oauth2-imap-authenticator)
;;
;; 4. (optional):
;; oauth2 uses plstore to save access tokens in ~/emacs.d/oauth2.plstore,
;; which is GPG-encrypted.  This allows the GPG passphrase to be cached
;; during the Emacs session:
;;
;; (setq plstore-cache-passphrase-for-symmetric-encryption t)
;;
;; 5. (optional):
;; plstore file doesn't end in newline.  Don't ask when saving (after the first time).
;;
;; (defun disable-final-newline ()
;;   (if (equal (file-name-extension buffer-file-name)
;;              "plstore")
;;       (setq require-final-newline nil)))
;; (add-hook 'write-file-functions 'disable-final-newline)

;;; Code:

(require 'google-oauth)

(defvar gnus-gmail-oauth-client-id nil
  "Client ID for OAuth.")

(defvar gnus-gmail-oauth-client-secret nil
  "Gnus secret key.")

(defconst gnus-gmail-resource-url "https://mail.google.com/"
  "URL used to request access to GMail.")

(defun gnus-gmail-oauth-token ()
  "Get OAuth token for Gnus to access GMail."
  (let ((token (google-oauth-auth-and-store
	       gnus-gmail-resource-url
	       gnus-gmail-oauth-client-id
	       gnus-gmail-oauth-client-secret)))
    ;; HACK -- always refresh
    (oauth2-refresh-access token)
    token))

(defun gnus-gmail-oauth2-imap-authenticator (user password)
  "Authenticator for GMail OAuth2.  Use as before-until advice for nnimap-login
See:  https://developers.google.com/gmail/xoauth2_protocol"
  (if (nnimap-capability "AUTH=XOAUTH2")
      (let ((token (gnus-gmail-oauth-token))
	    access-token)
	(setq access-token (oauth2-token-access-token token))
	(if (or (null token)
		(null access-token))
	    nil
	  (let (sequence challenge)
	    (erase-buffer)
	    (setq sequence (nnimap-send-command
			    "AUTHENTICATE XOAUTH2 %s"
			    (base64-encode-string
			     (format "user=%s\001auth=Bearer %s\001\001"
				     (nnimap-quote-specials user)
				     (nnimap-quote-specials access-token)))))
	    (setq challenge (nnimap-wait-for-line "^\\(.*\\)\n"))
	    ;; on successful authentication, first line is capabilities,
	    ;; next line is response
	    (if (string-match "^\\* CAPABILITY" challenge)
		(let (response (nnimap-get-response sequence))
		  (cons t response))
	      ;; send empty response on error
	      (let (response)
		(erase-buffer)
		(process-send-string
		 (get-buffer-process (current-buffer))
		 "\r\n")
		(setq response (nnimap-get-response sequence))
		(nnheader-report 'nnimap "%s"
				 (mapconcat (lambda (a)
					      (format "%s" a))
					    (car response) " "))
		nil)))))))

(provide 'gnus-gmail-oauth)
