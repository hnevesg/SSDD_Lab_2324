#!/usr/bin/env python3

import tempfile
import unittest
from pathlib import Path
from ..authentication import User, Authentication
import json

FILE_NO_EXIST = "no existe"
WRONG_JSON = 'wrong.json'

class TestsBasicos(unittest.TestCase):

	auth = Authentication()

	def test_wrong_user_instantation(self):
		with self.assertRaises(TypeError):
			User()

	def test_instantation_no_file(self):
		with self.assertRaises(FileNotFoundError):
			with tempfile.TemporaryDirectory() as workspace:
				f =	Path(workspace).joinpath(FILE_NO_EXIST)
				with open(f,'r') as contents: 
					contents.read()

	def test_instantation_bad_json(self):
			with tempfile.TemporaryDirectory() as workspace:
				f =	Path(workspace).joinpath(WRONG_JSON)
				with open(f, 'w') as contents:
					contents.write('{"key": "value",}')

				with self.assertRaises(json.JSONDecodeError):
					with open(f, 'r') as contents:
						json.loads(contents.read())
