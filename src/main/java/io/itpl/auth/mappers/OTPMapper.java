package io.itpl.auth.mappers;

import io.itpl.auth.dto.response.OTPResponse;
import io.itpl.auth.models.OTP;
import org.mapstruct.Mapper;
import org.mapstruct.NullValuePropertyMappingStrategy;

@Mapper(componentModel = "spring", nullValuePropertyMappingStrategy = NullValuePropertyMappingStrategy.IGNORE)
public interface OTPMapper {
  OTPResponse toResponse(OTP otp);
}
