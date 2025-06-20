import random
import string
import secrets
import re
from typing import List, Optional, Dict, Any

try:
    from wonderwords import RandomWords

    HAS_WONDERWORDS = True
except ImportError:
    HAS_WONDERWORDS = False

try:
    from random_word import RandomWords as RandomWord

    HAS_RANDOM_WORD = True
except ImportError:
    HAS_RANDOM_WORD = False


class PasswordGenerator:
    def __init__(self):
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.digits = string.digits
        self.special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        self.ambiguous_chars = "il1Lo0O"
        self.word_generator = None
        self.fallback_words = [
            "apple", "mountain", "river", "sunset", "forest", "ocean", "thunder",
            "crystal", "dragon", "phoenix", "wizard", "castle", "garden", "rainbow",
            "butterfly", "diamond", "golden", "silver", "storm", "cloud", "moon",
            "star", "fire", "water", "earth", "wind", "light", "shadow", "dream",
            "magic", "knight", "sword", "shield", "crown", "tower", "bridge", "flower",
            "tiger", "eagle", "wolf", "bear", "lion", "shark", "falcon", "panther",
            "ruby", "emerald", "sapphire", "topaz", "pearl", "jade", "amber", "coral",
            "hammer", "blade", "arrow", "spear", "axe", "bow", "staff", "wand",
            "winter", "summer", "spring", "autumn", "frost", "blaze", "mist", "dawn"
        ]
        self.init_word_generator()

    def init_word_generator(self):
        if HAS_WONDERWORDS:
            try:
                self.word_generator = RandomWords()
            except:
                pass
        elif HAS_RANDOM_WORD:
            try:
                self.word_generator = RandomWord()
            except:
                pass

    def get_random_word(self, min_length=3, max_length=10):
        if self.word_generator:
            try:
                if HAS_WONDERWORDS:
                    return self.word_generator.word(
                        word_min_length=min_length,
                        word_max_length=max_length
                    )
                elif HAS_RANDOM_WORD:
                    word = self.word_generator.get_random_word()
                    if word and min_length <= len(word) <= max_length:
                        return word
            except:
                pass

        suitable_words = [w for w in self.fallback_words if min_length <= len(w) <= max_length]
        return secrets.choice(suitable_words) if suitable_words else secrets.choice(self.fallback_words)

    def generate_password(self, length=12, use_uppercase=True, use_lowercase=True,
                          use_digits=True, use_special=True, exclude_ambiguous=False,
                          min_uppercase=1, min_lowercase=1, min_digits=1, min_special=1):
        if length < 4:
            raise ValueError("Password too short")

        char_pool = ""
        required_chars = []

        if use_lowercase:
            chars = self.lowercase
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.ambiguous_chars)
            char_pool += chars
            required_chars.extend(secrets.choice(chars) for _ in range(min_lowercase))

        if use_uppercase:
            chars = self.uppercase
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.ambiguous_chars)
            char_pool += chars
            required_chars.extend(secrets.choice(chars) for _ in range(min_uppercase))

        if use_digits:
            chars = self.digits
            if exclude_ambiguous:
                chars = ''.join(c for c in chars if c not in self.ambiguous_chars)
            char_pool += chars
            required_chars.extend(secrets.choice(chars) for _ in range(min_digits))

        if use_special:
            char_pool += self.special_chars
            required_chars.extend(secrets.choice(self.special_chars) for _ in range(min_special))

        if not char_pool:
            raise ValueError("No character types selected")

        if len(required_chars) > length:
            raise ValueError("Requirements exceed password length")

        remaining_length = length - len(required_chars)
        password_chars = required_chars + [secrets.choice(char_pool) for _ in range(remaining_length)]
        secrets.SystemRandom().shuffle(password_chars)
        return ''.join(password_chars)

    def generate_memorable_password(self, num_words=4, separator="-", add_numbers=True,
                                    capitalize=True, word_min_length=3, word_max_length=8):
        selected_words = []
        for _ in range(num_words):
            word = self.get_random_word(word_min_length, word_max_length)
            selected_words.append(word)

        if capitalize:
            selected_words = [word.capitalize() for word in selected_words]

        password = separator.join(selected_words)

        if add_numbers:
            password += str(secrets.randbelow(1000)).zfill(3)

        return password

    def generate_complex_memorable_password(self, num_words=3, add_special_chars=True,
                                            add_numbers=True, transform_words=True, min_length=16):
        words = []
        for _ in range(num_words):
            word = self.get_random_word(4, 8)

            if transform_words:
                transformations = [
                    lambda w: w.capitalize(),
                    lambda w: w.upper(),
                    lambda w: w.lower(),
                    lambda w: w.capitalize() if len(w) > 4 else w.upper()
                ]
                word = secrets.choice(transformations)(word)

                if secrets.randbelow(3) == 0:
                    replacements = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
                    for letter, digit in replacements.items():
                        if letter in word.lower() and secrets.randbelow(2) == 0:
                            word = word.replace(letter, digit).replace(letter.upper(), digit)
                            break

            words.append(word)

        separators = ['', '-', '_', '.', '!', '@', '#']
        password = ""

        for i, word in enumerate(words):
            password += word
            if i < len(words) - 1:
                if add_special_chars and secrets.randbelow(2) == 0:
                    password += secrets.choice(separators[3:])
                else:
                    password += secrets.choice(separators[:3])

        if add_numbers:
            number_positions = ['start', 'middle', 'end']
            position = secrets.choice(number_positions)
            number = str(secrets.randbelow(9999)).zfill(2)

            if position == 'start':
                password = number + password
            elif position == 'end':
                password = password + number
            else:
                mid = len(password) // 2
                password = password[:mid] + number + password[mid:]

        while len(password) < min_length and add_special_chars:
            special_char = secrets.choice("!@#$%^&*")
            position = secrets.randbelow(len(password) + 1)
            password = password[:position] + special_char + password[position:]

        return password

    def generate_password_by_complexity(self, complexity=5):
        if not 1 <= complexity <= 10:
            raise ValueError("Complexity must be 1-10")

        if complexity <= 2:
            length = 8 + complexity
            use_uppercase = complexity >= 2
            use_lowercase = True
            use_digits = complexity >= 2
            use_special = False
            exclude_ambiguous = True
            min_uppercase = 1 if use_uppercase else 0
            min_lowercase = 2
            min_digits = 1 if use_digits else 0
            min_special = 0

        elif complexity <= 4:
            length = 10 + complexity
            use_uppercase = True
            use_lowercase = True
            use_digits = True
            use_special = complexity >= 4
            exclude_ambiguous = complexity <= 3
            min_uppercase = 1
            min_lowercase = 2
            min_digits = 1
            min_special = 1 if use_special else 0

        elif complexity <= 6:
            length = 12 + complexity
            use_uppercase = True
            use_lowercase = True
            use_digits = True
            use_special = True
            exclude_ambiguous = False
            min_uppercase = 2
            min_lowercase = 2
            min_digits = 2
            min_special = 1

        elif complexity <= 8:
            length = 16 + (complexity - 6) * 2
            use_uppercase = True
            use_lowercase = True
            use_digits = True
            use_special = True
            exclude_ambiguous = False
            min_uppercase = 2
            min_lowercase = 3
            min_digits = 2
            min_special = 2

        else:
            length = 20 + (complexity - 8) * 4
            use_uppercase = True
            use_lowercase = True
            use_digits = True
            use_special = True
            exclude_ambiguous = False
            min_uppercase = 3
            min_lowercase = 4
            min_digits = 3
            min_special = 3

        return self.generate_password(
            length=length,
            use_uppercase=use_uppercase,
            use_lowercase=use_lowercase,
            use_digits=use_digits,
            use_special=use_special,
            exclude_ambiguous=exclude_ambiguous,
            min_uppercase=min_uppercase,
            min_lowercase=min_lowercase,
            min_digits=min_digits,
            min_special=min_special
        )

    def get_complexity_description(self, complexity):
        descriptions = {
            1: "Very Simple - lowercase only (9 chars)",
            2: "Simple - letters and digits (10 chars)",
            3: "Basic - letters and digits, no ambiguous (13 chars)",
            4: "Medium - all types, no ambiguous (14 chars)",
            5: "Good - all character types (17 chars)",
            6: "Strong - all types, more requirements (18 chars)",
            7: "Very Strong - increased length (18 chars)",
            8: "Excellent - high requirements (20 chars)",
            9: "Maximum - very long and complex (24 chars)",
            10: "Extreme - maximum protection (28 chars)"
        }
        return descriptions.get(complexity, "Unknown level")

    def build_custom_password(self, components):
        password_parts = []

        for component in components:
            comp_type = component.get('type', 'text')

            if comp_type == 'text':
                password_parts.append(component.get('value', ''))

            elif comp_type == 'word':
                word_config = component.get('config', {})
                word = self.get_random_word(
                    word_config.get('min_length', 3),
                    word_config.get('max_length', 10)
                )

                if word_config.get('capitalize', False):
                    word = word.capitalize()
                elif word_config.get('uppercase', False):
                    word = word.upper()
                elif word_config.get('lowercase', False):
                    word = word.lower()
                elif word_config.get('random_case', False):
                    word = ''.join(
                        char.upper() if secrets.randbelow(2) == 0 else char.lower()
                        for char in word
                    )

                replacements = word_config.get('replacements', {})
                for old, new in replacements.items():
                    word = word.replace(old, new)

                password_parts.append(word)

            elif comp_type == 'random_chars':
                char_config = component.get('config', {})
                length = char_config.get('length', 4)
                char_types = char_config.get('types', ['lowercase', 'uppercase', 'digits'])

                char_pool = ""
                if 'lowercase' in char_types:
                    char_pool += self.lowercase
                if 'uppercase' in char_types:
                    char_pool += self.uppercase
                if 'digits' in char_types:
                    char_pool += self.digits
                if 'special' in char_types:
                    char_pool += self.special_chars

                if char_pool:
                    random_chars = ''.join(secrets.choice(char_pool) for _ in range(length))
                    password_parts.append(random_chars)

            elif comp_type == 'number':
                num_config = component.get('config', {})
                min_val = num_config.get('min', 0)
                max_val = num_config.get('max', 9999)
                padding = num_config.get('padding', 0)

                number = str(secrets.randbelow(max_val - min_val + 1) + min_val)
                if padding > 0:
                    number = number.zfill(padding)

                password_parts.append(number)

            elif comp_type == 'separator':
                separators = component.get('options', ['-', '_', '.', '!', '@', '#'])
                password_parts.append(secrets.choice(separators))

        return ''.join(password_parts)

    def check_password_strength(self, password):
        score = 0
        feedback = []

        if len(password) >= 16:
            score += 3
        elif len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1
        else:
            feedback.append("Too short")

        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in self.special_chars for c in password)

        char_types = sum([has_lower, has_upper, has_digit, has_special])
        score += char_types

        if char_types < 3:
            feedback.append("Use different character types")

        unique_chars = len(set(password))
        if unique_chars >= len(password) * 0.8:
            score += 2
        elif unique_chars >= len(password) * 0.6:
            score += 1
        else:
            feedback.append("Too many repeated characters")

        patterns = [
            r'(.)\1{2,}',
            r'(012|123|234|345|456|567|678|789|890)',
            r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)',
            r'(qwe|wer|ert|rty|tyu|yui|uio|iop|asd|sdf|dfg|fgh|ghj|hjk|jkl|zxc|xcv|cvb|vbn|bnm)'
        ]

        pattern_found = False
        for pattern in patterns:
            if re.search(pattern, password.lower()):
                pattern_found = True
                break

        if pattern_found:
            score -= 2
            feedback.append("Avoid simple sequences")

        common_passwords = ["password", "123456", "qwerty", "admin", "login", "welcome"]
        if any(common in password.lower() for common in common_passwords):
            score -= 3
            feedback.append("Avoid common passwords")

        if score >= 10:
            strength = "Excellent"
        elif score >= 8:
            strength = "Very Strong"
        elif score >= 6:
            strength = "Strong"
        elif score >= 4:
            strength = "Medium"
        elif score >= 2:
            strength = "Weak"
        else:
            strength = "Very Weak"

        return {
            "score": max(0, score),
            "strength": strength,
            "feedback": feedback,
            "length": len(password),
            "has_lowercase": has_lower,
            "has_uppercase": has_upper,
            "has_digits": has_digit,
            "has_special": has_special,
            "unique_chars": unique_chars
        }


def ask_yes_no(prompt, default=True):
    default_text = "y" if default else "n"
    while True:
        answer = input(f"{prompt} (y/n, default {default_text}): ").strip().lower()
        if not answer:
            return default
        if answer in ['y', 'yes']:
            return True
        elif answer in ['n', 'no']:
            return False
        else:
            print("Please enter 'y' or 'n'")


def ask_number(prompt, min_val=1, max_val=100, default=None):
    while True:
        try:
            if default is not None:
                user_input = input(f"{prompt} (default {default}): ").strip()
                if not user_input:
                    return default
            else:
                user_input = input(f"{prompt}: ").strip()

            value = int(user_input)
            if min_val <= value <= max_val:
                return value
            else:
                print(f"Value must be between {min_val} and {max_val}")
        except ValueError:
            print("Please enter a valid number")


def ask_string(prompt, default=None):
    if default:
        user_input = input(f"{prompt} (default '{default}'): ").strip()
        return user_input if user_input else default
    else:
        return input(f"{prompt}: ").strip()


def show_menu():
    print("\n" + "=" * 50)
    print("           PASSWORD GENERATOR")
    print("=" * 50)
    print("1. Standard password")
    print("2. Memorable password")
    print("3. Complex memorable password")
    print("4. Custom password builder")
    print("5. Multiple passwords")
    print("6. Check password strength")
    print("7. Quick generation")
    print("8. Generate by complexity level")
    print("0. Exit")
    print("=" * 50)


def create_standard_password(gen):
    print("\n--- STANDARD PASSWORD ---")

    length = ask_number("Password length", min_val=4, max_val=128, default=12)

    print("\nCharacter types:")
    use_uppercase = ask_yes_no("Use uppercase letters (A-Z)?", True)
    use_lowercase = ask_yes_no("Use lowercase letters (a-z)?", True)
    use_digits = ask_yes_no("Use digits (0-9)?", True)
    use_special = ask_yes_no("Use special characters (!@#$%^&*)?", True)

    if not any([use_uppercase, use_lowercase, use_digits, use_special]):
        print("At least one character type must be selected. Enabling all types.")
        use_uppercase = use_lowercase = use_digits = use_special = True

    exclude_ambiguous = ask_yes_no("Exclude ambiguous characters (i,l,1,L,o,0,O)?", False)

    print("\nMinimum requirements (0 = not required):")
    min_uppercase = 0
    min_lowercase = 0
    min_digits = 0
    min_special = 0

    if use_uppercase:
        min_uppercase = ask_number("Minimum uppercase letters", min_val=0, max_val=length // 2, default=1)
    if use_lowercase:
        min_lowercase = ask_number("Minimum lowercase letters", min_val=0, max_val=length // 2, default=1)
    if use_digits:
        min_digits = ask_number("Minimum digits", min_val=0, max_val=length // 2, default=1)
    if use_special:
        min_special = ask_number("Minimum special characters", min_val=0, max_val=length // 2, default=1)

    try:
        password = gen.generate_password(
            length=length,
            use_uppercase=use_uppercase,
            use_lowercase=use_lowercase,
            use_digits=use_digits,
            use_special=use_special,
            exclude_ambiguous=exclude_ambiguous,
            min_uppercase=min_uppercase,
            min_lowercase=min_lowercase,
            min_digits=min_digits,
            min_special=min_special
        )

        print(f"\nGenerated password: {password}")

        analysis = gen.check_password_strength(password)
        print(f"Password strength: {analysis['strength']} (score: {analysis['score']})")

        if ask_yes_no("\nSave password to file?", False):
            save_password_to_file(password)

    except ValueError as e:
        print(f"Error: {e}")


def create_memorable_password(gen):
    print("\n--- MEMORABLE PASSWORD ---")

    num_words = ask_number("Number of words", min_val=2, max_val=8, default=4)

    print("\nChoose separator:")
    print("1. Hyphen (-)")
    print("2. Underscore (_)")
    print("3. Dot (.)")
    print("4. No separator")

    separator_choice = ask_number("Choose option", min_val=1, max_val=4, default=1)
    separators = ["-", "_", ".", ""]
    separator = separators[separator_choice - 1]

    capitalize = ask_yes_no("Capitalize first letters?", True)
    add_numbers = ask_yes_no("Add numbers at the end?", True)

    word_min_length = ask_number("Minimum word length", min_val=3, max_val=10, default=4)
    word_max_length = ask_number("Maximum word length", min_val=word_min_length, max_val=15, default=8)

    password = gen.generate_memorable_password(
        num_words=num_words,
        separator=separator,
        add_numbers=add_numbers,
        capitalize=capitalize,
        word_min_length=word_min_length,
        word_max_length=word_max_length
    )

    print(f"\nGenerated password: {password}")

    analysis = gen.check_password_strength(password)
    print(f"Password strength: {analysis['strength']} (score: {analysis['score']})")

    if ask_yes_no("\nSave password to file?", False):
        save_password_to_file(password)


def create_complex_memorable_password(gen):
    print("\n--- COMPLEX MEMORABLE PASSWORD ---")

    num_words = ask_number("Number of words", min_val=2, max_val=6, default=3)
    add_special_chars = ask_yes_no("Add special characters?", True)
    add_numbers = ask_yes_no("Add numbers?", True)
    transform_words = ask_yes_no("Apply word transformations (letter to number replacements)?", True)
    min_length = ask_number("Minimum password length", min_val=12, max_val=50, default=16)

    print("\nGenerating options...")

    for i in range(3):
        password = gen.generate_complex_memorable_password(
            num_words=num_words,
            add_special_chars=add_special_chars,
            add_numbers=add_numbers,
            transform_words=transform_words,
            min_length=min_length
        )

        analysis = gen.check_password_strength(password)
        print(f"\n{i + 1}. {password}")
        print(f"   Strength: {analysis['strength']} | Length: {analysis['length']} | Score: {analysis['score']}")

    choice = ask_number("\nChoose password to save (1-3, 0 = don't save)", min_val=0, max_val=3, default=0)

    if choice > 0:
        final_password = gen.generate_complex_memorable_password(
            num_words=num_words,
            add_special_chars=add_special_chars,
            add_numbers=add_numbers,
            transform_words=transform_words,
            min_length=min_length
        )

        print(f"\nSelected password: {final_password}")

        if ask_yes_no("Save password to file?", False):
            save_password_to_file(final_password)


def create_password_by_complexity(gen):
    print("\n--- PASSWORD BY COMPLEXITY LEVEL ---")
    print("Choose complexity level from 1 to 10:")
    print()

    for i in range(1, 11):
        print(f"{i:2d}. {gen.get_complexity_description(i)}")

    print()
    complexity = ask_number("Choose complexity level", min_val=1, max_val=10, default=5)

    print(f"\nSelected level: {gen.get_complexity_description(complexity)}")

    count = ask_number("Number of password variants", min_val=1, max_val=10, default=3)

    print(f"\nGenerated passwords (complexity level {complexity}):")
    passwords = []

    for i in range(count):
        try:
            password = gen.generate_password_by_complexity(complexity)
            passwords.append(password)

            analysis = gen.check_password_strength(password)

            print(f"\n{i + 1}. {password}")
            print(f"   Strength: {analysis['strength']} | Length: {analysis['length']} | Score: {analysis['score']}/15")

            composition = []
            if analysis['has_lowercase']:
                composition.append("lowercase")
            if analysis['has_uppercase']:
                composition.append("uppercase")
            if analysis['has_digits']:
                composition.append("digits")
            if analysis['has_special']:
                composition.append("special")

            print(f"   Composition: {', '.join(composition)}")

        except ValueError as e:
            print(f"Error generating password {i + 1}: {e}")

    if passwords:
        if ask_yes_no("\nSave passwords to file?", False):
            save_passwords_to_file(passwords)

        if len(passwords) > 1 and ask_yes_no("Save one selected password separately?", False):
            choice = ask_number(f"Choose password (1-{len(passwords)})", min_val=1, max_val=len(passwords))
            save_password_to_file(passwords[choice - 1])


def build_custom_password_interactive(gen):
    print("\n--- CUSTOM PASSWORD BUILDER ---")
    print("Build a password from components of your choice!")
    print("\nAvailable component types:")
    print("1. Text (fixed string)")
    print("2. Random word")
    print("3. Random characters")
    print("4. Number")
    print("5. Separator")

    components = []

    while True:
        print(f"\n--- Component #{len(components) + 1} ---")
        print("Choose component type:")
        print("1. Text")
        print("2. Random word")
        print("3. Random characters")
        print("4. Number")
        print("5. Separator")
        print("6. Finish and create password")
        print("0. Cancel")

        choice = ask_number("Your choice", min_val=0, max_val=6)

        if choice == 0:
            return
        elif choice == 6:
            break
        elif choice == 1:
            text = ask_string("Enter text")
            if text:
                components.append({'type': 'text', 'value': text})

        elif choice == 2:
            print("\nWord settings:")
            min_len = ask_number("Minimum word length", min_val=2, max_val=15, default=4)
            max_len = ask_number("Maximum word length", min_val=min_len, max_val=20, default=8)

            print("\nTransformation:")
            print("1. No changes")
            print("2. Capitalize first letter")
            print("3. All uppercase")
            print("4. All lowercase")
            print("5. Random case")

            transform = ask_number("Choose transformation", min_val=1, max_val=5, default=2)

            config = {
                'min_length': min_len,
                'max_length': max_len,
                'capitalize': transform == 2,
                'uppercase': transform == 3,
                'lowercase': transform == 4,
                'random_case': transform == 5
            }

            if ask_yes_no("Add letter to number replacements (a->4, e->3, etc)?", False):
                config['replacements'] = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5'}

            components.append({'type': 'word', 'config': config})

        elif choice == 3:
            length = ask_number("Length", min_val=1, max_val=20, default=4)

            print("\nCharacter types:")
            types = []
            if ask_yes_no("Lowercase letters?", True):
                types.append('lowercase')
            if ask_yes_no("Uppercase letters?", True):
                types.append('uppercase')
            if ask_yes_no("Digits?", True):
                types.append('digits')
            if ask_yes_no("Special characters?", False):
                types.append('special')

            if types:
                components.append({
                    'type': 'random_chars',
                    'config': {'length': length, 'types': types}
                })

        elif choice == 4:
            min_val = ask_number("Minimum value", min_val=0, max_val=999999, default=0)
            max_val = ask_number("Maximum value", min_val=min_val, max_val=999999, default=999)
            padding = ask_number("Pad with zeros to length (0 = no padding)", min_val=0, max_val=10, default=0)

            components.append({
                'type': 'number',
                'config': {'min': min_val, 'max': max_val, 'padding': padding}
            })

        elif choice == 5:
            print("\nChoose separator:")
            print("1. Hyphen (-)")
            print("2. Underscore (_)")
            print("3. Dot (.)")
            print("4. Exclamation (!)")
            print("5. At sign (@)")
            print("6. Hash (#)")
            print("7. Random from all")
            print("8. Custom")

            sep_choice = ask_number("Choice", min_val=1, max_val=8, default=7)

            if sep_choice == 8:
                custom_separators = ask_string("Enter possible separators").split()
                if custom_separators:
                    components.append({'type': 'separator', 'options': custom_separators})
            else:
                sep_options = [
                    ['-'], ['_'], ['.'], ['!'], ['@'], ['#'],
                    ['-', '_', '.', '!', '@', '#']
                ]
                components.append({'type': 'separator', 'options': sep_options[sep_choice - 1]})

        print(f"Component added! Total components: {len(components)}")

    if not components:
        print("No components added")
        return

    print(f"\nCreating password from {len(components)} components...")

    for i in range(3):
        password = gen.build_custom_password(components)
        analysis = gen.check_password_strength(password)
        print(f"\n{i + 1}. {password}")
        print(f"   Strength: {analysis['strength']} | Length: {analysis['length']} | Score: {analysis['score']}")

    if ask_yes_no("\nSave one of the passwords?", True):
        final_password = gen.build_custom_password(components)
        save_password_to_file(final_password)


def create_multiple_passwords(gen):
    print("\n--- MULTIPLE PASSWORDS ---")

    count = ask_number("Number of passwords to generate", min_val=1, max_val=50, default=5)

    print("\nChoose password type:")
    print("1. Standard passwords")
    print("2. Memorable passwords")
    print("3. Complex memorable passwords")

    password_type = ask_number("Choose type", min_val=1, max_val=3, default=1)

    print(f"\nGenerated passwords:")
    passwords = []

    if password_type == 1:
        length = ask_number("Password length", min_val=4, max_val=128, default=12)
    elif password_type == 2:
        num_words = ask_number("Number of words", min_val=2, max_val=8, default=4)
    else:
        num_words = ask_number("Number of words", min_val=2, max_val=6, default=3)

    for i in range(count):
        try:
            if password_type == 1:
                password = gen.generate_password(length=length)
            elif password_type == 2:
                password = gen.generate_memorable_password(num_words=num_words)
            else:
                password = gen.generate_complex_memorable_password(num_words=num_words)

            passwords.append(password)
            analysis = gen.check_password_strength(password)
            print(f"{i + 1:2d}. {password} | {analysis['strength']} ({analysis['score']} points)")

        except ValueError as e:
            print(f"Error generating password {i + 1}: {e}")

    if passwords and ask_yes_no("\nSave all passwords to file?", False):
        save_passwords_to_file(passwords)


def check_password_strength(gen):
    print("\n--- PASSWORD STRENGTH CHECK ---")

    password = input("Enter password to check: ").strip()

    if not password:
        print("Password cannot be empty")
        return

    analysis = gen.check_password_strength(password)

    print(f"\nPASSWORD ANALYSIS: '{password}'")
    print("=" * 50)
    print(f"Password strength: {analysis['strength']}")
    print(f"Length: {analysis['length']} characters")
    print(f"Score: {analysis['score']}/15")
    print(f"Unique characters: {analysis['unique_chars']}")

    print("\nPassword composition:")
    print(f"   • Lowercase letters: {'✓' if analysis['has_lowercase'] else '✗'}")
    print(f"   • Uppercase letters: {'✓' if analysis['has_uppercase'] else '✗'}")
    print(f"   • Digits: {'✓' if analysis['has_digits'] else '✗'}")
    print(f"   • Special characters: {'✓' if analysis['has_special'] else '✗'}")

    if analysis['feedback']:
        print("\nRecommendations:")
        for tip in analysis['feedback']:
            print(f"   • {tip}")


def quick_generate(gen):
    print("\n--- QUICK GENERATION ---")

    print("Choose quick generation type:")
    print("1. Standard password (16 characters)")
    print("2. Short password (8 characters)")
    print("3. Long password (24 characters)")
    print("4. Memorable password")
    print("5. Complex memorable password")

    quick_type = ask_number("Choose type", min_val=1, max_val=5, default=1)
    count = ask_number("Number of passwords", min_val=1, max_val=10, default=3)

    print(f"\nGenerated passwords:")
    passwords = []

    for i in range(count):
        if quick_type == 1:
            password = gen.generate_password(length=16)
        elif quick_type == 2:
            password = gen.generate_password(length=8)
        elif quick_type == 3:
            password = gen.generate_password(length=24)
        elif quick_type == 4:
            password = gen.generate_memorable_password()
        else:
            password = gen.generate_complex_memorable_password()

        passwords.append(password)
        analysis = gen.check_password_strength(password)
        print(f"{i + 1}. {password} | {analysis['strength']}")

    if ask_yes_no("\nSave passwords to file?", False):
        save_passwords_to_file(passwords)


def save_password_to_file(password):
    try:
        import datetime
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with open("password.txt", "w", encoding="utf-8") as f:
            f.write(f"Generated password ({timestamp}):\n")
            f.write(f"{password}\n")
        print("Password saved to 'password.txt'")
    except Exception as e:
        print(f"Error saving: {e}")


def save_passwords_to_file(passwords):
    try:
        import datetime
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with open("passwords.txt", "w", encoding="utf-8") as f:
            f.write(f"Generated passwords ({timestamp}):\n")
            f.write("=" * 40 + "\n")
            for i, password in enumerate(passwords, 1):
                f.write(f"{i}. {password}\n")
        print(f"{len(passwords)} passwords saved to 'passwords.txt'")
    except Exception as e:
        print(f"Error saving: {e}")


def main():
    gen = PasswordGenerator()

    print("Welcome to Password Generator!")
    print("Checking word libraries availability...")

    while True:
        show_menu()

        try:
            choice = input("\nChoose action (0-8): ").strip()

            if choice == "0":
                print("\nGoodbye! Keep your passwords safe!")
                break
            elif choice == "1":
                create_standard_password(gen)
            elif choice == "2":
                create_memorable_password(gen)
            elif choice == "3":
                create_complex_memorable_password(gen)
            elif choice == "4":
                build_custom_password_interactive(gen)
            elif choice == "5":
                create_multiple_passwords(gen)
            elif choice == "6":
                check_password_strength(gen)
            elif choice == "7":
                quick_generate(gen)
            elif choice == "8":
                create_password_by_complexity(gen)
            else:
                print("Invalid choice. Try again.")

        except KeyboardInterrupt:
            print("\n\nProgram interrupted. Goodbye!")
            break
        except Exception as e:
            print(f"Error occurred: {e}")
            print("Try again or choose another option.")

        input("\nPress Enter to continue...")


if __name__ == "__main__":
    main()
