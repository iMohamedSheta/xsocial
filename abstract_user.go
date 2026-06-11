package xsocial

// AbstractUser implements the User interface
type AbstractUser struct {
	// The unique identifier for the user
	ID any `json:"id"`

	// The user's nickname / username
	Nickname string `json:"nickname"`

	// The user's full name
	Name string `json:"name"`

	// The user's e-mail address
	Email string `json:"email"`

	// The user's avatar image URL
	Avatar string `json:"avatar"`

	// The user's raw attributes
	User map[string]any `json:"user"`

	// The user's other attributes
	Attributes map[string]any `json:"attributes"`
}

// NewAbstractUser creates a new abstract user instance
func NewAbstractUser() *AbstractUser {
	return &AbstractUser{
		User:       make(map[string]any),
		Attributes: make(map[string]any),
	}
}

// GetID gets the unique identifier for the user
func (u *AbstractUser) GetID() any {
	return u.ID
}

// GetNickname gets the nickname / username for the user
func (u *AbstractUser) GetNickname() string {
	return u.Nickname
}

// GetName gets the full name of the user
func (u *AbstractUser) GetName() string {
	return u.Name
}

// GetEmail gets the e-mail address of the user
func (u *AbstractUser) GetEmail() string {
	return u.Email
}

// GetAvatar gets the avatar / image URL for the user
func (u *AbstractUser) GetAvatar() string {
	return u.Avatar
}

// GetRaw gets the raw user array
func (u *AbstractUser) GetRaw() map[string]any {
	return u.User
}

// SetRaw sets the raw user array from the provider
func (u *AbstractUser) SetRaw(user map[string]any) *AbstractUser {
	u.User = user
	return u
}

// Map maps the given array onto the user's properties
func (u *AbstractUser) Map(attributes map[string]any) *AbstractUser {
	u.Attributes = attributes

	for key, value := range attributes {
		switch key {
		case "id":
			u.ID = value
		case "nickname":
			if str, ok := value.(string); ok {
				u.Nickname = str
			}
		case "name":
			if str, ok := value.(string); ok {
				u.Name = str
			}
		case "email":
			if str, ok := value.(string); ok {
				u.Email = str
			}
		case "avatar":
			if str, ok := value.(string); ok {
				u.Avatar = str
			}
		}
	}

	return u
}

// OffsetExists determines if the given raw user attribute exists
func (u *AbstractUser) OffsetExists(offset string) bool {
	_, exists := u.User[offset]
	return exists
}

// OffsetGet gets the given key from the raw user
func (u *AbstractUser) OffsetGet(offset string) any {
	return u.User[offset]
}

// OffsetSet sets the given attribute on the raw user array
func (u *AbstractUser) OffsetSet(offset string, value any) {
	u.User[offset] = value
}

// OffsetUnset unsets the given value from the raw user array
func (u *AbstractUser) OffsetUnset(offset string) {
	delete(u.User, offset)
}

// Get gets a user attribute value dynamically
func (u *AbstractUser) Get(key string) any {
	if val, ok := u.Attributes[key]; ok {
		return val
	}
	return nil
}

// Set sets a user attribute value dynamically
func (u *AbstractUser) Set(key string, value any) {
	u.Attributes[key] = value
}

// Has checks if an attribute exists
func (u *AbstractUser) Has(key string) bool {
	_, exists := u.Attributes[key]
	return exists
}
