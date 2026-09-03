__all__ = [
    'hr',
    'hrx',
    'clean'
]

#===
def hr(char: str = None, size: int = None) -> None:
    if char is None:
        char = '-'
    if size is None:
        size = 30
    print(f'{char*size}')
    
def hrx() -> None:
    """
    `hrx` -- Horizontal Rule 2.

    Large horizontal rule

    Args:
        NA

    Returns:
        NA
    
    Raises:
        NA

    Example:
        >>> hrx()
        expected_output:
        ```
    
        ====================
        
        ```
    """
    print()
    hr(
        char='=',
        size=80
    )    
    print()
    
def clean(string: str, funcs = None) -> str:
    if not funcs:
        funcs = [str.strip, str.lower]
        
    for func in funcs:
        string = func(string)
        
    return string