package io.itpl.auth.mappers;

import io.itpl.auth.dto.request.AuthRequest;
import io.itpl.auth.models.Account;
import org.mapstruct.Mapper;
import org.mapstruct.NullValuePropertyMappingStrategy;

@Mapper(componentModel = "spring", nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
public interface AccountMapper {
  Account toEntity(AuthRequest authRequest);
}
