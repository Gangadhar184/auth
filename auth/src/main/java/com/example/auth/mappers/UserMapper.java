package com.example.auth.mappers;

import com.example.auth.dtos.UserDto;
import com.example.auth.models.User;
import org.springframework.stereotype.Component;

@Component
public class UserMapper {

    //Server → Client
    public UserDto toDto(User user){
        if(user == null) return null;

        return UserDto.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .roles(user.getRoles())
                .enabled(user.getEnabled())
                .build();

    }

    // Client → Server
    public User toEntity(UserDto userDto) {
        if (userDto == null) {
            return null;
        }

        return User.builder()
                .id(userDto.getId())
                .username(userDto.getUsername())
                .email(userDto.getEmail())
                .roles(userDto.getRoles())
                .enabled(userDto.getEnabled())
                .build();
    }

    public void updateEntity(User existingUser, UserDto userDto) {
        if (existingUser == null || userDto == null) {
            return;
        }

        if (userDto.getUsername() != null) {
            existingUser.setUsername(userDto.getUsername());
        }

        if (userDto.getEmail() != null) {
            existingUser.setEmail(userDto.getEmail());
        }

        if (userDto.getRoles() != null) {
            existingUser.setRoles(userDto.getRoles());
        }

        if (userDto.getEnabled() != null) {
            existingUser.setEnabled(userDto.getEnabled());
        }
    }
}
