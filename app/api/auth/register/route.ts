import { NextRequest, NextResponse } from 'next/server';
import * as bcrypt from 'bcryptjs';
import { sanitizeString, validateEmail, validateUsername, validatePassword, checkRateLimit } from '@/lib/validation';
import { createUser, findUserByIdentifier } from '@/lib/data/users';

export async function POST(request: NextRequest) {
  console.log('Register API called');
  
  try {
    const body = await request.json();
    console.log('Request body received');
    
    const { username, email, password, role } = body;

    // Input validation
    if (!username || !email || !password) {
      console.log('Missing required fields');
      return NextResponse.json(
        { error: 'Tüm alanlar zorunludur' },
        { status: 400 }
      );
    }

    // Sanitize inputs
    const sanitizedUsername = sanitizeString(username.trim());
    const sanitizedEmail = sanitizeString(email.trim().toLowerCase());
    const sanitizedRole = sanitizeString(role || 'user');

    console.log('Sanitized:', { username: sanitizedUsername, email: sanitizedEmail });

    // Validate format
    if (!validateUsername(sanitizedUsername)) {
      return NextResponse.json(
        { error: 'Kullanıcı adı geçersiz (3-30 karakter, sadece harf, rakam, _ ve -)' },
        { status: 400 }
      );
    }

    if (!validateEmail(sanitizedEmail)) {
      return NextResponse.json(
        { error: 'Email formatı geçersiz' },
        { status: 400 }
      );
    }

    if (!validatePassword(password)) {
      return NextResponse.json(
        { error: 'Şifre en az 6 karakter olmalıdır' },
        { status: 400 }
      );
    }

    // Whitelist role values
    if (!['user', 'admin', 'doctor'].includes(sanitizedRole)) {
      return NextResponse.json(
        { error: 'Geçersiz rol' },
        { status: 400 }
      );
    }

    // Rate limiting
    const clientIp = request.headers.get('x-forwarded-for') || 'unknown';
    if (!checkRateLimit(`register:${clientIp}`, 10, 60000)) {
      return NextResponse.json(
        { error: 'Çok fazla istek. Lütfen bekleyin.' },
        { status: 429 }
      );
    }

    // Check if username or email already exists
    const existingUser = await findUserByIdentifier(sanitizedUsername);
    const existingByEmail = await findUserByIdentifier(sanitizedEmail);

    if (existingUser || existingByEmail) {
      return NextResponse.json(
        { error: 'Bu kullanıcı adı veya email zaten kullanılıyor' },
        { status: 400 }
      );
    }

    console.log('Hashing password...');
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    console.log('Creating user...');
    const user = await createUser({
      username: sanitizedUsername,
      email: sanitizedEmail,
      password: hashedPassword,
      role: sanitizedRole,
      isActive: true
    });
    console.log('User created:', user.username);

    return NextResponse.json({
      success: true,
      user: {
        id: user.id.toString(),
        username: user.username,
        email: user.email,
        role: user.role,
        isActive: user.is_active,
        createdAt: user.created_at
      }
    }, { status: 201 });

  } catch (error) {
    console.error('Register hatası detayı:', error);
    return NextResponse.json(
      { 
        error: 'Kayıt başarısız',
        details: error instanceof Error ? error.message : 'Bilinmeyen hata'
      },
      { status: 500 }
    );
  }
}

