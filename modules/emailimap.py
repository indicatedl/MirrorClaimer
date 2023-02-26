import imaplib
import email
import quopri
import base64

class emailImap:
    def __init__(self, address, password, server, folder):
        self.address = address
        self.password = password
        self.server = server
        self.folder = folder
    
    def get_number_of_mails(self):
        imap = imaplib.IMAP4_SSL(self.server)
        imap.login(self.address, self.password)
        status, result = imap.select(self.folder)
        imap.logout()
        return (int(result[0]))

    def get_mail_by_id(self, mail_id):
        imap = imaplib.IMAP4_SSL(self.server)
        imap.login(self.address, self.password)
        status, result = imap.select(self.folder)
        res, msg = imap.fetch(mail_id, '(RFC822)') 
        msg = email.message_from_bytes(msg[0][1])
        mail_data = msg.as_bytes().decode('latin-1')
        imap.logout()
        return mail_data

    def get_last_mail(self):
        imap = imaplib.IMAP4_SSL(self.server)
        imap.login(self.address, self.password)
        status, result = imap.select(self.folder)
        number_of_mails = result[0]
        res, msg = imap.fetch(number_of_mails, '(RFC822)') 
        mail_text = ''
        msg = email.message_from_bytes(msg[0][1])
        for part in msg.walk():
            if part.get_content_maintype() == 'text' and part.get_content_subtype() == 'plain':
                mail_text += quopri.decodestring(part.get_payload()).decode('latin-1')
        imap.logout()
        return mail_text

    def get_new_mail(self, mail_num_before):
        while True:
            mail_num = self.get_number_of_mails()
            if (mail_num != mail_num_before):
                break
        mail_text = self.get_mail_by_id(str(mail_num))
        return mail_text
