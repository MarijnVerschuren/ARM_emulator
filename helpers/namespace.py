__all__ = [
	"namespace"
]


class namespace:
	def __init__(self, **kwargs: any) -> None:
		for name in kwargs:
			setattr(self, name, kwargs[name])

	def __contains__(self, key: any) -> bool:			return key in self.__dict__
	def __getitem__(self, key: any) -> any:				return self.__dict__[key]
	def __setitem__(self, key: any, val: any) -> None:	self.__dict__[key] = val
	def __delitem__(self, key: any) -> None:			del self.__dict__[key]

	def __str__(self) -> str:							return f"<namespace({', '.join([f'{key}={val}' for key, val in self.__dict__.items()])})>"
	def __repr__(self) -> str:							return self.__str__()
	def __len__(self) -> int:							return len(self.__dict__.keys())
