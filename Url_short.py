from app import Link
import string
import random





def genearate_short_url():
     
    # Generate a random short URL
    characters= string.ascii_letters + string.digits
    short_url= ''.join(random.choices(characters) for _ in range(6))
    print(f'Generated short URL: {short_url}')
    
    # Ensure the short URL is unique
    existing_link= Link.query.filter_by(short_url=short_url).first()
    if existing_link:
        return genearate_short_url()
    return short_url