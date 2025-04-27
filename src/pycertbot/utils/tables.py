
from tabulate import tabulate

def _get_short_uuid(full_uuid):
	return full_uuid.split("-")[0]

def get_from_json(data_list, header_list=None, short_uuid=True):
	if len(data_list) == 0:
		return None

	headers = header_list

	if headers == None:
		headers = list(data_list[0].keys())
	table = []
	for data in data_list:
		row = []
		for key in headers:
			value = data[key]
			if short_uuid and key == "uuid":
				value = _get_short_uuid(value)
			row.append(value)
		table.append(row)

	out = tabulate(table, headers, tablefmt="simple", stralign="center")
	return out
