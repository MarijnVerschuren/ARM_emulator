def safe_input(prompt: str, expect: type) -> int | float | bool | str:
	while True:
		try:
			data = input(prompt)
			if expect == int:
				data = data.lower().strip("ul")
				if data.startswith("0x"):	data = int(data, 16)
				elif data.endswith("h"):	data = int(data[:-1], 16)
				elif data.startswith("0o"):	data = int(data, 8)
				else:						data = int(data)
			elif expect == float:			data = float(data)
			elif expect == bool:			data = bool(data)
			return data
		except ValueError as e: pass