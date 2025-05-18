import unittest
import requests
import time

BASE_URL = 'http://127.0.0.1:5000'

class APITest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        timestamp = int(time.time())
        cls.login = f'azzamkulovshokhruz@gmail.com'
        cls.password = 'Passw0rd!'
        cls.full_name = 'Test User'
        cls.phone = f'+7701{timestamp % 10000000:07d}'
        cls.iin = f'{timestamp % 1000000000000:012d}'
        cls.access_token = None
        cls.refresh_token = None

    def test_01_email_confirm(self):
        url = f"{BASE_URL}/signup/verify"
        payload = {'login': self.login}
        r = requests.post(url, json=payload)
        self.assertEqual(r.status_code, 200)

    def test_02_check_email_confirm(self):
        url = f"{BASE_URL}/signup/verify/check"
        payload = {'login': self.login}
        max_wait = 60  # макс. 60 секунд ожидания
        waited = 0

        while waited < max_wait:
            r = requests.post(url, json=payload)
            try:
                data = r.json()
            except ValueError:
                self.fail("Response is not JSON")
                return

            print(data)

            if r.status_code != 200:
                self.fail(f"Unexpected status code: {r.status_code}")
            if data.get("confirmed"):
                break

            time.sleep(5)
            waited += 5
        else:
            self.fail("Email was not confirmed within timeout")

        #print(r.json())

        # Можно оставить или убрать, если уже проверили статус выше
        self.assertEqual(r.status_code, 200)


    def test_03_signup(self):
        url = f"{BASE_URL}/signup"
        payload = {
            'login': self.login,
            'password': self.password,
            'full_name': self.full_name,
            'phone': self.phone,
            'role': '',
            'iin': self.iin
        }
        r = requests.post(url, json=payload)
        self.assertEqual(r.status_code, 201, r.text)
        data = r.json()
        self.assertTrue(data.get('login'))
        self.assertIn('access_token', data)
        self.assertIn('refresh_token', data)
        APITest.access_token = data['access_token']
        APITest.refresh_token = data['refresh_token']

    def test_04_check_login_available(self):
        url = f"{BASE_URL}/signup/checkavailable/login"
        r = requests.get(url, params={'value': self.login})
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertTrue(data.get('login'))

    def test_05_check_phone_available(self):
        url = f"{BASE_URL}/signup/checkavailable/phone"
        r = requests.get(url, params={'value': self.phone})
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertTrue(data.get('phone'))

    def test_06_check_iin_available(self):
        url = f"{BASE_URL}/signup/checkavailable/iin"
        r = requests.get(url, params={'value': self.iin})
        self.assertEqual(r.status_code, 200)
        data = r.json()
        self.assertTrue(data.get('iin'))

    def test_07_login_once(self):
        url = f"{BASE_URL}/login"
        payload = {'login': self.login, 'password': self.password}
        r = requests.post(url, json=payload)
        self.assertEqual(r.status_code, 200, r.text)
        data = r.json()
        self.assertTrue(data.get('login'))
        self.assertIn('access_token', data)
        self.assertIn('refresh_token', data)
        APITest.access_token = data['access_token']
        APITest.refresh_token = data['refresh_token']

    def test_08_refresh(self):
        url = f"{BASE_URL}/refresh"
        headers = {'Authorization': f"Bearer {self.refresh_token}"}
        r = requests.post(url, headers=headers)
        self.assertEqual(r.status_code, 200, r.text)
        data = r.json()
        self.assertIn('access_token', data)
        APITest.access_token = data['access_token']

    def test_09_update_login(self):
        new_login = self.login.replace('@', '_upd@')
        url = f"{BASE_URL}/update/login"
        headers = {'Authorization': f"Bearer {self.access_token}"}
        payload = {'login': self.login, 'new_login': new_login}
        r = requests.patch(url, json=payload, headers=headers)
        self.assertIn(r.status_code, (200, 409), r.text)
        if r.status_code == 200:
            APITest.login = new_login

    def test_10_create_and_get_document(self):
        url = f"{BASE_URL}/documents"
        headers = {'Authorization': f"Bearer {self.access_token}"}
        payload = {'login': self.login, 'name': 'Doc1', 'content': 'Hello'}
        r = requests.post(url, json=payload, headers=headers)
        self.assertEqual(r.status_code, 201, r.text)
        doc_id = r.json().get('doc_id')
        self.assertIsInstance(doc_id, int)

        r2 = requests.get(f"{BASE_URL}/documents", params={'login': self.login}, headers=headers)
        self.assertEqual(r2.status_code, 200)
        docs = r2.json()
        self.assertIsInstance(docs, dict)
        self.assertIn(str(doc_id), docs)

        r3 = requests.get(f"{BASE_URL}/documents/{doc_id}", params={'login': self.login}, headers=headers)
        self.assertEqual(r3.status_code, 200)
        single = r3.json()
        self.assertIn('doc_name', single)
        self.assertIn('content', single)

    def test_11_update_password(self):
        new_pwd = self.password + 'X'
        url = f"{BASE_URL}/update/password"
        headers = {'Authorization': f"Bearer {self.access_token}"}
        payload = {'login': self.login, 'new_password': new_pwd}
        r = requests.patch(url, json=payload, headers=headers)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json().get('password'))
        # проверяем новый пароль
        r2 = requests.post(f"{BASE_URL}/login", json={'login': self.login, 'password': new_pwd})
        self.assertEqual(r2.status_code, 200)

    def test_12_update_phone(self):
        new_phone = self.phone[:-1] + '0'
        url = f"{BASE_URL}/update/phone"
        headers = {'Authorization': f"Bearer {self.access_token}"}
        payload = {'login': self.login, 'new_phone': new_phone}
        r = requests.patch(url, json=payload, headers=headers)
        if r.status_code == 200:
            self.assertTrue(r.json().get('phone'))
            APITest.phone = new_phone
        else:
            self.assertEqual(r.status_code, 409)

    def test_13_add_and_list_contacts(self):
        contact = 'friend@example.com'
        url = f"{BASE_URL}/contacts"
        headers = {'Authorization': f"Bearer {self.access_token}"}
        payload = {'login': self.login, 'contact': contact}
        r = requests.post(url, json=payload, headers=headers)
        self.assertEqual(r.status_code, 201, r.text)
        con_id = r.json().get('con_id')
        self.assertIsInstance(con_id, int)

        r2 = requests.get(url, params={'login': self.login}, headers=headers)
        self.assertEqual(r2.status_code, 200)
        contacts = r2.json()
        self.assertIn(str(con_id), contacts)
        self.assertEqual(contacts[str(con_id)], contact)

    def test_14_remove_contact(self):
        contact = 'friend2@example.com'
        url = f"{BASE_URL}/contacts"
        headers = {'Authorization': f"Bearer {self.access_token}"}
        payload = {'login': self.login, 'contact': contact}
        r = requests.post(url, json=payload, headers=headers)
        con_id = r.json().get('con_id')
        r2 = requests.delete(f"{BASE_URL}/contacts/{con_id}", params={'login': self.login}, headers=headers)
        self.assertEqual(r2.status_code, 200, r2.text)
        self.assertTrue(r2.json().get('removed'))

    def test_15_subdocument_crud(self):
        url = f"{BASE_URL}/documents"
        headers = {'Authorization': f"Bearer {self.access_token}"}
        r = requests.post(url, json={'login': self.login, 'name': 'DocSub', 'content': ''}, headers=headers)
        doc_id = r.json().get('doc_id')

        url_sub = f"{BASE_URL}/documents/{doc_id}/subdocuments"
        payload_sub = {'login': self.login, 'name': 'SubDoc', 'content': 'SubContent'}
        r2 = requests.post(url_sub, json=payload_sub, headers=headers)
        self.assertEqual(r2.status_code, 201, r2.text)
        sub_id = r2.json().get('subdocument_id')

        r3 = requests.patch(f"{BASE_URL}/documents/{doc_id}/subdocuments/{sub_id}", json={'login': self.login, 'name': 'SubUpdated'}, headers=headers)
        self.assertEqual(r3.status_code, 200)

        r4 = requests.delete(f"{BASE_URL}/documents/{doc_id}/subdocuments/{sub_id}", params={'login': self.login}, headers=headers)
        self.assertEqual(r4.status_code, 200)
        self.assertTrue(r4.json().get('deleted'))

    def test_16_upload_and_list_files(self):
        url = f"{BASE_URL}/documents"
        headers = {'Authorization': f"Bearer {self.access_token}"}
        r = requests.post(url, json={'login': self.login}, headers=headers)
        doc_id = r.json().get('doc_id')

        url_file = f"{BASE_URL}/documents/{doc_id}/files"
        files = {'file': ('test.txt', b'hello world')}
        r2 = requests.post(url_file, files=files, headers=headers)
        self.assertEqual(r2.status_code, 201)
        u_doc_id = r2.json().get('u_doc_id')
        
        r3 = requests.get(url_file, params={'login': self.login}, headers=headers)
        self.assertEqual(r3.status_code, 200)
        files_list = r3.json()
        self.assertIn(str(u_doc_id), files_list)

    def test_17_add_and_list_comments(self):
        url = f"{BASE_URL}/documents"
        headers = {'Authorization': f"Bearer {self.access_token}"}
        r = requests.post(url, json={'login': self.login}, headers=headers)
        doc_id = r.json().get('doc_id')

        url_c = f"{BASE_URL}/comment"
        payload = {'login': self.login, 'doc_id': doc_id, 'content': 'Nice doc!'}
        r2 = requests.post(url_c, json=payload, headers=headers)
        self.assertEqual(r2.status_code, 201)
        com_id = r2.json().get('comment_id')

        r3 = requests.get(url_c, params={'login': self.login, 'doc_id': doc_id}, headers=headers)
        self.assertEqual(r3.status_code, 200)
        comments = r3.json()
        self.assertIn(str(com_id), comments)

if __name__ == '__main__':
    unittest.main()
