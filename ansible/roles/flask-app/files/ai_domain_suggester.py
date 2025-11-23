#!/usr/bin/env python3
"""
AI-Powered Domain Name Suggestion Engine
Uses OpenAI GPT-4 for intelligent, context-aware domain suggestions
"""

import openai
import re
from typing import List, Dict, Any
import logging
from datetime import datetime
import json

logger = logging.getLogger(__name__)


class AIDomainSuggester:
    """AI-powered domain name suggestion engine using OpenAI GPT-4"""

    def __init__(self, api_key: str):
        """Initialize with OpenAI API key"""
        self.api_key = api_key
        openai.api_key = api_key

    def generate_suggestions(
        self,
        keywords: List[str],
        industry: str = None,
        style: str = "creative",
        count: int = 50,
        tlds: List[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Generate AI-powered domain suggestions

        Args:
            keywords: List of keywords/concepts
            industry: Industry/niche (e.g., "tech", "healthcare", "finance")
            style: Suggestion style ("creative", "professional", "brandable", "descriptive")
            count: Number of suggestions to generate
            tlds: List of TLDs to suggest (.com, .ai, .io, etc.)

        Returns:
            List of domain suggestions with metadata
        """
        if tlds is None:
            tlds = [".com", ".io", ".ai", ".co", ".app", ".dev"]

        try:
            # Build the AI prompt
            prompt = self._build_prompt(keywords, industry, style, count, tlds)

            # Call OpenAI API
            response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert domain name consultant specializing in creating memorable, brandable, and SEO-friendly domain names. You understand naming trends, linguistic patterns, and what makes domains valuable."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.8,  # Higher creativity
                max_tokens=2000,
                n=1
            )

            # Parse the response
            suggestions_text = response.choices[0].message.content
            suggestions = self._parse_ai_response(suggestions_text, tlds)

            # Enhance with metadata
            enhanced = []
            for suggestion in suggestions[:count]:
                enhanced.append({
                    "domain": suggestion["domain"],
                    "explanation": suggestion.get("explanation", ""),
                    "category": suggestion.get("category", style),
                    "memorability_score": suggestion.get("score", 0),
                    "ai_generated": True,
                    "timestamp": datetime.utcnow().isoformat()
                })

            return enhanced

        except Exception as e:
            logger.error(f"AI suggestion generation failed: {e}")
            # Fallback to algorithmic suggestions
            return self._fallback_suggestions(keywords, tlds, count)

    def _build_prompt(
        self,
        keywords: List[str],
        industry: str,
        style: str,
        count: int,
        tlds: List[str]
    ) -> str:
        """Build the GPT-4 prompt"""

        keywords_str = ", ".join(keywords)
        tlds_str = ", ".join(tlds)

        style_descriptions = {
            "creative": "unique, memorable, and brandable names that stand out",
            "professional": "credible, authoritative names suitable for established businesses",
            "brandable": "short, catchy names perfect for building a brand",
            "descriptive": "clear, SEO-friendly names that explain what the business does",
            "modern": "trendy, tech-forward names using modern naming conventions",
            "premium": "high-value, prestigious names suitable for premium brands"
        }

        style_desc = style_descriptions.get(style, style_descriptions["creative"])

        industry_context = f" in the {industry} industry" if industry else ""

        prompt = f"""Generate {count} domain name suggestions{industry_context} based on these keywords: {keywords_str}

Style: {style_desc}

Requirements:
1. Each domain should be available (uncommon/unique combinations)
2. Easy to spell and pronounce
3. Memorable and brandable
4. Use these TLDs: {tlds_str}
5. Mix of:
   - Short names (1-2 words, <10 chars)
   - Compound words
   - Creative spellings
   - Portmanteaus (blended words)
   - Modern tech-style names

Format each suggestion as:
DOMAIN: example.com
EXPLANATION: Brief reason why this is a good choice
CATEGORY: creative/professional/brandable/etc
SCORE: 1-10 memorability score

Provide exactly {count} suggestions."""

        return prompt

    def _parse_ai_response(self, response_text: str, tlds: List[str]) -> List[Dict[str, Any]]:
        """Parse AI response into structured suggestions"""

        suggestions = []
        current = {}

        for line in response_text.split('\n'):
            line = line.strip()

            if line.startswith('DOMAIN:'):
                if current and 'domain' in current:
                    suggestions.append(current)
                    current = {}
                domain = line.replace('DOMAIN:', '').strip()
                # Clean up the domain
                domain = re.sub(r'[^\w.-]', '', domain.lower())
                current['domain'] = domain

            elif line.startswith('EXPLANATION:'):
                current['explanation'] = line.replace('EXPLANATION:', '').strip()

            elif line.startswith('CATEGORY:'):
                current['category'] = line.replace('CATEGORY:', '').strip().lower()

            elif line.startswith('SCORE:'):
                try:
                    score_text = line.replace('SCORE:', '').strip()
                    score = int(re.search(r'\d+', score_text).group())
                    current['score'] = min(score, 10)
                except:
                    current['score'] = 7  # Default

        # Add the last one
        if current and 'domain' in current:
            suggestions.append(current)

        return suggestions

    def _fallback_suggestions(
        self,
        keywords: List[str],
        tlds: List[str],
        count: int
    ) -> List[Dict[str, Any]]:
        """Fallback algorithmic suggestions if AI fails"""

        suggestions = []
        prefixes = ["get", "my", "the", "go", "try", "use", "find"]
        suffixes = ["app", "hub", "lab", "hq", "pro", "zone", "base"]

        # Generate combinations
        for keyword in keywords:
            keyword = keyword.lower().replace(" ", "")

            # Direct + TLD
            for tld in tlds[:3]:
                suggestions.append({
                    "domain": f"{keyword}{tld}",
                    "explanation": f"Direct keyword match with {tld}",
                    "category": "direct",
                    "memorability_score": 6,
                    "ai_generated": False
                })

            # Prefix combinations
            for prefix in prefixes[:3]:
                for tld in tlds[:2]:
                    suggestions.append({
                        "domain": f"{prefix}{keyword}{tld}",
                        "explanation": f"Actionable name with '{prefix}' prefix",
                        "category": "actionable",
                        "memorability_score": 7,
                        "ai_generated": False
                    })

            # Suffix combinations
            for suffix in suffixes[:3]:
                for tld in tlds[:2]:
                    suggestions.append({
                        "domain": f"{keyword}{suffix}{tld}",
                        "explanation": f"Brandable name with '{suffix}' suffix",
                        "category": "brandable",
                        "memorability_score": 7,
                        "ai_generated": False
                    })

        return suggestions[:count]

    def batch_generate(
        self,
        keywords: List[str],
        page: int = 1,
        per_page: int = 20,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Generate paginated suggestions

        Args:
            keywords: Search keywords
            page: Page number (1-indexed)
            per_page: Results per page
            **kwargs: Additional args for generate_suggestions

        Returns:
            Dict with suggestions, pagination info
        """
        # Generate more than needed for pagination
        total_to_generate = page * per_page + 100

        all_suggestions = self.generate_suggestions(
            keywords=keywords,
            count=total_to_generate,
            **kwargs
        )

        # Calculate pagination
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page

        page_suggestions = all_suggestions[start_idx:end_idx]

        return {
            "suggestions": page_suggestions,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": len(all_suggestions),
                "total_pages": (len(all_suggestions) + per_page - 1) // per_page,
                "has_next": end_idx < len(all_suggestions),
                "has_prev": page > 1
            },
            "metadata": {
                "keywords": keywords,
                "generated_at": datetime.utcnow().isoformat(),
                "ai_powered": True
            }
        }


# Convenience function
def get_ai_suggestions(
    keywords: List[str],
    api_key: str,
    page: int = 1,
    per_page: int = 20,
    **kwargs
) -> Dict[str, Any]:
    """Quick helper to get AI domain suggestions"""

    suggester = AIDomainSuggester(api_key)
    return suggester.batch_generate(
        keywords=keywords,
        page=page,
        per_page=per_page,
        **kwargs
    )
