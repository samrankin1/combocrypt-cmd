import getopt
import json
import uuid
import sys
import os

from enum import Enum

from combocrypt.combocrypt import ComboCrypt

AES_KEYSIZE = 256 # use 256-bit AES keys
RSA_KEYSIZE = 4096 # use 4096-bit RSA keys

PUBLIC_KEY_EXTENSION = ".pubkey"
PRIVATE_KEY_EXTENSION = ".privkey"
ENCRYPTED_FILE_EXTENSION = ".enc"

arg_mode = None
arg_key_file = None
arg_input_file = None
arg_output_file = None

class FileType(Enum):
	public_key = 0
	private_key = 1
	encrypted_file = 2

class Mode(Enum):
	generate = 0
	encrypt = 1
	decrypt = 2

def file_type_by_extension(file_path):
	file = file_path

	if not file:
		return None

	public_key_extension = file[-len(PUBLIC_KEY_EXTENSION):]
	if public_key_extension == PUBLIC_KEY_EXTENSION:
		return FileType.public_key

	private_key_extension = file[-len(PRIVATE_KEY_EXTENSION):]
	if private_key_extension == PRIVATE_KEY_EXTENSION:
		return FileType.private_key

	encrypted_file_extension = file[-len(ENCRYPTED_FILE_EXTENSION):]
	if encrypted_file_extension == ENCRYPTED_FILE_EXTENSION:
		return FileType.encrypted_file

	return None

def get_unique_name():
	long_uuid = str(uuid.uuid1()) # generate a long UUID (ex. a74f046e-3195-11e6-95da-5cf3707022e4)
	dash_index = long_uuid.find("-") # find the index of the first dash in the UUID string
	short_uuid = long_uuid[:dash_index] # use only the part of the UUID before the first dash
	return short_uuid

def print_help_message():
	print("combocrypt-cmd.py (--mode (generate | encrypt | decrypt) | -g | -e | -d) [(--key | -k) <key file>] [(--input | -i) <input file>] [(--output | -o) <output file>]")

	print()
	print()
	print()

	print("Generation Mode:")
	print()
	print("randomly generate a new RSA keypair, optionally specifying where to save the generated keys")
	print()
	print("combocrypt-cmd.py (--mode generate | -g) [(--output | -o) <output file>]")
	print()
	print("ex.: combocrypt-cmd.py --mode generate --output mykey")
	print()
	print("example generates a keypair and saves them to 'mykey.privkey' and 'mykey.pubkey' in the local directory")

	print()
	print()
	print()

	print("Encryption Mode:")
	print()
	print("encrypt a specified file with the specified recipient's public key, optionally specifying where to save the encrypted file (defaults to local directory, input file with .enc appended)")
	print()
	print("combocrypt-cmd.py (--mode encrypt | -e) (--key | -k) <key file> (--input | -i) <input file> [(--output | -o) <output file>]")
	print()
	print("ex.: combocrypt-cmd.py --mode encrypt --key mykey.pubkey -i secretfiles.zip -o supersecret.zip.enc")
	print()
	print("example encrypts 'secretfiles.zip' in the local directory with the public key 'mykey.pubkey', outputting the result to 'supersecret.zip.enc'")

	print()
	print()
	print()

	print("Decryption Mode:")
	print()
	print("decrypt a file previously encrypted by combocrypt-cmd.py, using the specified recipient's private key, optionally specifying where to save the decrypted file")
	print()
	print("combocrypt-cmd.py (--mode decrypt | -d) (--key | -k) <key file> (--input | -i) <input file> [(--output | -o) <output file>]")
	print()
	print("ex.: combocrypt-cmd.py --mode decrypt --key mykey.privkey -i supersecret.zip.enc -o decrypted.zip")
	print()
	print("example decrypts the already-encrypted file 'supersecret.zip.enc' with the private key 'mykey.privkey', outputting the result to 'decrypted.zip'")

	sys.exit(0)

def print_usage_string():
	print("combocrypt-cmd.py (--mode (generate | encrypt | decrypt) | -g | -e | -d) [(--key | -k) <key file>] [(--input | -i) <input file>] [(--output | -o) <output file>]")
	print()
	print("for more info, use --help")

	sys.exit(0)

def process_args():
	global arg_mode
	global arg_key_file
	global arg_input_file
	global arg_output_file

	raw_args = sys.argv[1:]
	opts, args = getopt.gnu_getopt(raw_args, 'gedm:k:i:o:', ["mode=", "key=", "input=", "output=", "help"]) # generate; encrypt; decrypt; --mode / -m; --key / -k; --input / -i; --output / -o

	opts_dict = {k : v for k, v in opts} # list of tuples to dictionary of args and their values

	mode_values = {
		"generate" : Mode.generate,
		"encrypt" : Mode.encrypt,
		"decrypt" : Mode.decrypt
	}

	if "--help" in opts_dict:
		print_help_message()

	if "--mode" in opts_dict:
		value = opts_dict["--mode"]
		arg_mode = mode_values.get(value, None)

		if arg_mode == None:
			print("invalid value for --mode: '" + str(value) + "'; must be 'generate', 'encrypt', or 'decrypt'")
			print()
			print_usage_string()

	if "-m" in opts_dict:
		if arg_mode == None:
			value = opts_dict["-m"]
			arg_mode = mode_values.get(value, None)

			if arg_mode == None:
				print("invalid value for -m: '" + str(value) + "'; must be 'generate', 'encrypt', or 'decrypt'")
				print()
				print_usage_string()
		else:
			print("conflicting argument -m, arg_mode is already set to '" + str(arg_mode) + "'")
			print()
			print_usage_string()

	if "-g" in opts_dict:
		if arg_mode == None:
			arg_mode = Mode.generate
		else:
			print("conflicting argument -g, arg_mode is already set to '" + str(arg_mode) + "'")
			print()
			print_usage_string()

	if "-e" in opts_dict:
		if arg_mode == None:
			arg_mode = Mode.encrypt
		else:
			print("conflicting argument -e, arg_mode is already set to '" + str(arg_mode) + "'")
			print()
			print_usage_string()

	if "-d" in opts_dict:
		if arg_mode == None:
			arg_mode = Mode.decrypt
		else:
			print("conflicting argument -d, arg_mode is already set to '" + str(arg_mode) + "'")
			print()
			print_usage_string()

	if arg_mode == None:
		print("no mode specified, must be 'generate', 'encrypt', or 'decrypt'")
		print()
		print_usage_string()

	if "--key" in opts_dict:
		value = opts_dict["--key"]

		if not value:
			print("key file cannot be an empty string!")
			print()
			print_usage_string()

		arg_key_file = value

	if "-k" in opts_dict:
		if arg_key_file == None:
			value = opts_dict["-k"]

			if not value:
				print("key file cannot be an empty string!")
				print()
				print_usage_string()

			arg_key_file = value
		else:
			print("conflicting argument -k, arg_key_file is already set to '" + str(arg_key_file) + "'")

	if "--input" in opts_dict:
		value = opts_dict["--input"]

		if not value:
			print("input file cannot be an empty string!")
			print()
			print_usage_string()

		arg_input_file = value

	if "-i" in opts_dict:
		if arg_input_file == None:
			value = opts_dict["-i"]

			if not value:
				print("input file cannot be an empty string!")
				print()
				print_usage_string()

			arg_input_file = value
		else:
			print("conflicting argument -i, arg_input_file is already set to '" + str(arg_input_file) + "'")

	if "--output" in opts_dict:
		value = opts_dict["--output"]

		if not value:
			print("output file cannot be an empty string!")
			print()
			print_usage_string()

		arg_output_file = value

	if "-o" in opts_dict:
		if arg_output_file == None:
			value = opts_dict["-o"]

			if not value:
				print("output file cannot be an empty string!")
				print()
				print_usage_string()

			arg_output_file = value
		else:
			print("conflicting argument -o, arg_output_file is already set to '" + str(arg_output_file) + "'")

	# mode requirements check
	if arg_mode == Mode.generate: # cannot have a key-file or an input file
		if not arg_key_file == None:
			print("error: in generation mode, an existing key-file (--key, -k) cannot be specified; currently set to '" + arg_key_file + "'")
			print()
			print_usage_string()

		if not arg_input_file == None:
			print("error: in generation mode, an input file (--input, -i) cannot be specified; currently set to '" + arg_input_file + "'")
			print()
			print_usage_string()

		if arg_output_file == None:
			arg_output_file = get_unique_name()

	if arg_mode == Mode.encrypt: # requires a keyfile that is a public key and an input file
		if arg_key_file == None:
			print("error: in encrypt mode, an existing key-file (--key, -k) must be specified")
			print()
			print_usage_string()

		key_file_name = os.path.basename(arg_key_file)
		if "." not in key_file_name: # if the key file provided has no extension
			arg_key_file += PUBLIC_KEY_EXTENSION # assume public key extension

		if not file_type_by_extension(arg_key_file) == FileType.public_key:
			print("error: in encrypt mode, the specified key-file (--key, -k) must be a public key (" + PUBLIC_KEY_EXTENSION + ")")
			print()
			print_usage_string()

		if arg_input_file == None:
			print("error: in encrypt mode, an input file (--input, -i) must be specified")
			print()
			print_usage_string()

		if arg_output_file == None:
			arg_output_file = arg_input_file + ENCRYPTED_FILE_EXTENSION
			print("no output file specified, defaulting to '" + str(arg_output_file) + "'")
			print()
		else: # else if arg_output_file already exists
			output_file_name = os.path.basename(arg_output_file) # get the name of the output file
			if "." not in output_file_name: # if the output file provided has no extension
				arg_output_file += ENCRYPTED_FILE_EXTENSION # assume encrypted file extension

	if arg_mode == Mode.decrypt:
		if arg_key_file == None:
			print("error: in decrypt mode, an existing key-file (--key, -k) must be specified")
			print()
			print_usage_string()

		multikey_mode = os.path.isdir(arg_key_file)

		key_file_name = os.path.basename(arg_key_file)
		if (not multikey_mode) and ("." not in key_file_name): # if the key file provided has no extension
			arg_key_file += PRIVATE_KEY_EXTENSION # assume private key extension

		if (not multikey_mode) and (not file_type_by_extension(arg_key_file) == FileType.private_key):
			print("error: in decrypt mode, the specified key-file (--key, -k) must be a private key (" + PRIVATE_KEY_EXTENSION + ") or a directory containing private keys")
			print()
			print_usage_string()

		if arg_input_file == None:
			print("error: in decrypt mode, an input file (--input, -i) must be specified")
			print()
			print_usage_string()

		if arg_output_file == None:
			# if the input file carries the encrypted file extension, remove it
			encrypted_file_extension = arg_input_file[-len(ENCRYPTED_FILE_EXTENSION):]
			if encrypted_file_extension == ENCRYPTED_FILE_EXTENSION:
				arg_output_file = arg_input_file[:-len(ENCRYPTED_FILE_EXTENSION)]
			else:
				arg_output_file = arg_input_file + "_decrypted"

			print("no output file specified, defaulting to '" + str(arg_output_file) + "'")
			print()

class GenerateStatus(Enum):
	error_duplicate_key = 0 # {key_type, key_file}
	generating = 1 # {key_size}
	writing = 2 # {private_key_file, public_key_file}
	done = 3 # {}

class EncryptStatus(Enum):
	loading = 0 # {key_file}
	encrypting = 1 # {input_file}
	writing = 2 # {output_file}
	done = 3 # {}

class DecryptStatus(Enum):
	error_multikey_empty = 0 # {key_file}
	loading = 1 # {key_file}
	decrypting = 2 # {input_file}
	multikey_failed = 3 # {key_file}
	singlekey_failed = 4 # {key_file}
	error_multikey_none_found = 5 # {key_file}
	writing = 6 # {output_file}
	done = 7 # {}

def do_generate(combocrypt, output_file):
	privkey_file = output_file + PRIVATE_KEY_EXTENSION
	pubkey_file = output_file + PUBLIC_KEY_EXTENSION

	if os.path.isfile(privkey_file):
		yield GenerateStatus.error_duplicate_key, {"key_type": FileType.private_key, "key_file": privkey_file}
		return
	elif os.path.isfile(pubkey_file):
		yield GenerateStatus.error_duplicate_key, {"key_type": FileType.public_key, "key_file": pubkey_file}
		return

	yield GenerateStatus.generating, {"key_size": RSA_KEYSIZE} # todo: combocrypt.get_RSA_keysize()
	privkey = combocrypt.rsa_random_keypair()
	pubkey = privkey.publickey()

	yield GenerateStatus.writing, {"private_key_file": privkey_file, "public_key_file": pubkey_file}
	ComboCrypt.save_rsa_key(privkey, privkey_file)
	ComboCrypt.save_rsa_key(pubkey, pubkey_file)

	yield GenerateStatus.done, {}

def do_encrypt(combocrypt, key_file, input_file, output_file):
	yield EncryptStatus.loading, {"key_file": key_file}
	pubkey = ComboCrypt.load_rsa_key(key_file)

	yield EncryptStatus.encrypting, {"input_file": input_file}
	encrypted = combocrypt.combo_encrypt_file(input_file, pubkey)

	yield EncryptStatus.writing, {"output_file": output_file}
	with open(output_file, "w") as writer:
		writer.write(encrypted)

	yield EncryptStatus.done, {}

def do_decrypt(combocrypt, key_file, input_file, output_file):
	multikey_mode = os.path.isdir(key_file)

	key_files = []

	if multikey_mode:
		files = [file for file in os.listdir(key_file) if os.path.isfile(os.path.join(key_file, file))] # create array of all the files in the given directory
		for file in files: # for each file in the directory
			if file_type_by_extension(file) == FileType.private_key: # if the file is a private key
				key_files.append(file) # add the possible key file to the list

		if not key_files:
			yield DecryptStatus.error_multikey_empty, {"key_file": key_file}
			return
	else:
		key_files.append(key_file)

	decrypted = None
	for key_file in key_files:
		yield DecryptStatus.loading, {"key_file": key_file}
		privkey = ComboCrypt.load_rsa_key(key_file)

		yield DecryptStatus.decrypting, {"input_file": input_file}
		try:
			decrypted = combocrypt.combo_decrypt_file(input_file, privkey)
			break
		except ValueError:
			if multikey_mode:
				yield DecryptStatus.multikey_failed, {"key_file": key_file}
				continue
			else:
				yield DecryptStatus.singlekey_failed, {"key_file": key_file}
				return

	if decrypted == None:
		yield DecryptStatus.error_multikey_none_found, {"key_file": key_file}
		return

	yield DecryptStatus.writing, {"output_file": output_file}
	with open(output_file, "wb") as writer:
		writer.write(decrypted)

	yield DecryptStatus.done, {}

def main():
	process_args()

	combocrypt = ComboCrypt(AES_KEYSIZE, RSA_KEYSIZE)

	if arg_mode == Mode.generate:
		for status, values in do_generate(combocrypt, arg_output_file):
			if status == GenerateStatus.error_duplicate_key:
				key_type = values["key_type"]
				key_file = values["key_file"]

				print("error: " + ("private" if (key_type == FileType.private_key) else "public") + " key file '" + key_file + "' already exists and cannot be overwritten!")
				sys.exit(0)

			if status == GenerateStatus.generating:
				key_size = values["key_size"]
				print("generating " + str(key_size) + "-bit RSA keypair...")

			if status == GenerateStatus.writing:
				private_key_file = values["private_key_file"]
				public_key_file = values["public_key_file"]

				print("writing keys to '" + private_key_file + "' and '" + public_key_file + "'...")

			if status == GenerateStatus.done:
				print()
				print("done!")
				print()
				print("warning: never share your private key file! anyone in possession of your private key can read messages meant for you!")

	elif arg_mode == Mode.encrypt:
		for status, values in do_encrypt(combocrypt, arg_key_file, arg_input_file, arg_output_file):
			if status == EncryptStatus.loading:
				key_file = values["key_file"]
				print("loading RSA key from '" + key_file + "'...")

			if status == EncryptStatus.encrypting:
				input_file = values["input_file"]
				print("encrypting file data...")

			if status == EncryptStatus.writing:
				output_file = values["output_file"]
				print("writing encrypted data as JSON to output file...")

			if status == EncryptStatus.done:
				print()
				print("done!")

	elif arg_mode == Mode.decrypt:
		for status, values in do_decrypt(combocrypt, arg_key_file, arg_input_file, arg_output_file):
			if status == DecryptStatus.error_multikey_empty:
				key_file = values["key_file"]

				print("error: --key argument folder '" + key_file + "' contains no private keys!")
				sys.exit(0)

			if status == DecryptStatus.loading:
				key_file = values["key_file"]
				print("loading RSA key from '" + key_file + "'...")

			if status == DecryptStatus.decrypting:
				input_file = values["input_file"]
				print("loading and decrypting file JSON...")

			if status == DecryptStatus.multikey_failed:
				key_file = values["key_file"]

				print("decryption failed, continuing...")
				print()

			if status == DecryptStatus.singlekey_failed:
				key_file = values["key_file"]

				print()
				print("error: decryption failed; ensure that the key argument is the *recipient's* private key")
				sys.exit(0)

			if status == DecryptStatus.error_multikey_none_found:
				key_file = values["key_file"]

				print()
				print("error: multikey folder '" + key_file + "' contained no suitable key")

			if status == DecryptStatus.writing:
				output_file = values["output_file"]
				print("writing decrypted data to output file...")

			if status == DecryptStatus.done:
				print()
				print("done!")

if __name__ == "__main__":
	main()
