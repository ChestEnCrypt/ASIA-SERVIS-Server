import unittest
import requests
import time

BASE_URL = 'http://127.0.0.1:5000'

class APITest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        timestamp = int(time.time())
        cls.login = f'test{timestamp}@example.com'
        cls.password = 'Passw0rd!'
        cls.full_name = 'Test User'
        cls.phone = f'+7701{timestamp % 10000000:07d}'
        cls.iin = f'{timestamp % 1000000000000:012d}'
        cls.access_token = None
        cls.refresh_token = None

    def test_01_signup(self):
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

    def test_02_check_login_available(self):
        url = f"{BASE_URL}/signup/checkavailable/login"
        r = requests.get(url, params={'value': self.login})
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.json().get('login'))

    def test_03_check_phone_available(self):
        url = f"{BASE_URL}/signup/checkavailable/phone"
        r = requests.get(url, params={'value': self.phone})
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.json().get('phone'))

    def test_04_check_iin_available(self):
        url = f"{BASE_URL}/signup/checkavailable/iin"
        r = requests.get(url, params={'value': self.iin})
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.json().get('iin'))

    def test_05_login_once(self):
        url = f"{BASE_URL}/login/once"
        payload = {'login': self.login, 'password': self.password}
        r = requests.post(url, json=payload)
        self.assertEqual(r.status_code, 200, r.text)
        data = r.json()
        self.assertTrue(data.get('login'))
        self.assertIn('access_token', data)
        self.assertIn('refresh_token', data)
        APITest.access_token = data['access_token']
        APITest.refresh_token = data['refresh_token']

    def test_06_refresh(self):
        url = f"{BASE_URL}/refresh"
        headers = {'Authorization': f"Bearer {self.refresh_token}"}
        r = requests.post(url, headers=headers)
        self.assertEqual(r.status_code, 200, r.text)
        data = r.json()
        self.assertIn('access_token', data)
        APITest.access_token = data['access_token']

    def test_07_update_login(self):
        new_login = self.login.replace('@', '_upd@')
        url = f"{BASE_URL}/update/login"
        headers = {'Authorization': f"Bearer {self.access_token}"}
        payload = {'login': self.login, 'new_login': new_login}
        r = requests.patch(url, json=payload, headers=headers)
        self.assertIn(r.status_code, (200, 409), r.text)
        if r.status_code == 200:
            APITest.login = new_login

    def test_08_create_and_get_document(self):
        # создание документа
        url = f"{BASE_URL}/documents"
        headers = {'Authorization': f"Bearer {self.access_token}"}
        payload = {'login': self.login, 'name': 'Doc1', 'content': 'Hello'}
        r = requests.post(url, json=payload, headers=headers)
        self.assertEqual(r.status_code, 201, r.text)
        doc_id = r.json().get('doc_id')
        self.assertIsInstance(doc_id, int)

        # получение списка документов
        url_list = f"{BASE_URL}/documents"
        r2 = requests.get(url_list, params={'login': self.login}, headers=headers)
        self.assertEqual(r2.status_code, 200)
        docs = r2.json()
        # API возвращает dict {doc_id: {...}}
        self.assertIsInstance(docs, dict)
        self.assertIn(str(doc_id), docs)

        # получение конкретного документа
        url_get = f"{BASE_URL}/documents/{doc_id}"
        r3 = requests.get(url_get, params={'login': self.login}, headers=headers)
        self.assertEqual(r3.status_code, 200)
        single = r3.json()
        # single содержит поля без id
        self.assertIn('doc_name', single)
        self.assertIn('content', single)

if __name__ == '__main__':
    unittest.main()
